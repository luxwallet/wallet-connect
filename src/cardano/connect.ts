/**
 * Cardano wallet connector — CIP-30 dApp API + CIP-8 `signData` (ed25519).
 *
 * Handshake (no SDK needed — CIP-30 is a thin injected surface):
 *   1. `window.cardano[id].enable()` → the CIP-30 API.
 *   2. Pick the signing address: a used payment address
 *      (`getUsedAddresses()` → CBOR-hex `addr…`) when available, else the
 *      reward/stake address (`getRewardAddresses()` → `stake…`). The hex bytes
 *      are rendered to bech32 (`addr1…`/`stake1…`) — the canonical proof address.
 *   3. `api.signData(addressHex, payloadHex)` (CIP-8) → `{ signature, key }`:
 *      a COSE_Sign1 (hex) and a COSE_Key (hex). The wallet signs the CAIP-122
 *      message bytes verbatim (non-hashed).
 *
 * The produced {@link SignedProof}: scheme `ed25519-cardano`, the bech32
 * `address`, the hex `publicKey` (from the COSE_Key), the hex `signature`
 * (COSE_Sign1), and `extra.coseKey` (the COSE_Key hex) — exactly what
 * {@link import('./verify.js').verifyCardano} needs.
 *
 * No hard dependency: this drives the raw injected CIP-30 API. CIP-30 wallet
 * libraries are OPTIONAL, browser-only — the verify core pulls NONE of them.
 */
import type {
  Account,
  LoginChallenge,
  SignedProof,
  WalletConnector,
  WalletInfo,
} from '../types.js';
import { buildSiwxMessage } from '../caip122.js';
import { utf8ToBytes, bytesToHex, hexToBytes } from '../bytes.js';
import { cborDecode } from './cbor.js';
import { bech32Encode } from './bech32.js';

/** What CIP-8 `signData` returns: COSE_Sign1 + COSE_Key, both hex. */
interface DataSignature {
  signature: string;
  key: string;
}

/** The subset of the CIP-30 API surface this connector uses. */
interface Cip30Api {
  getUsedAddresses(paginate?: { page: number; limit: number }): Promise<string[]>;
  getUnusedAddresses?(): Promise<string[]>;
  getRewardAddresses(): Promise<string[]>;
  getChangeAddress?(): Promise<string>;
  signData(addressHex: string, payloadHex: string): Promise<DataSignature>;
}

/** A wallet's entry in `window.cardano` before `enable()`. */
interface Cip30WalletEntry {
  name?: string;
  icon?: string;
  apiVersion?: string;
  enable(): Promise<Cip30Api>;
  isEnabled?(): Promise<boolean>;
}

interface CardanoWindow {
  cardano?: Record<string, Cip30WalletEntry>;
}

function getWindow(): CardanoWindow | undefined {
  return typeof window === 'undefined' ? undefined : (window as unknown as CardanoWindow);
}

/** Friendly names for the wallets we commonly see (fallback to the entry name). */
const WALLET_NAMES: Record<string, string> = {
  nami: 'Nami',
  eternl: 'Eternl',
  lace: 'Lace',
  flint: 'Flint',
  gerowallet: 'GeroWallet',
  typhoncip30: 'Typhon',
  yoroi: 'Yoroi',
  nufi: 'NuFi',
  vespr: 'Vespr',
};

/** CIP-30 entries are wallet objects; ignore non-conforming keys (e.g. helpers). */
function discover(win: CardanoWindow): { id: string; entry: Cip30WalletEntry }[] {
  const cardano = win.cardano;
  if (!cardano) return [];
  const out: { id: string; entry: Cip30WalletEntry }[] = [];
  for (const id of Object.keys(cardano)) {
    const entry = cardano[id];
    if (entry && typeof entry.enable === 'function') out.push({ id, entry });
  }
  return out;
}

/**
 * Render a CIP-30 hex address to its bech32 form. The first byte's high nibble
 * is the address type; reward/stake addresses (type 14/15) use the `stake` HRP,
 * everything else uses `addr`. Mainnet vs testnet is the header's low nibble
 * (1 = mainnet → `addr`/`stake`; 0 = testnet → `addr_test`/`stake_test`).
 */
function hexAddressToBech32(addressHex: string): string | null {
  let raw: Uint8Array;
  try {
    raw = hexToBytes(addressHex);
  } catch {
    return null;
  }
  if (raw.length < 1) return null;
  const header = raw[0]!;
  const type = header >> 4;
  const network = header & 0x0f;
  const isStake = type === 14 || type === 15;
  const mainnet = network === 1;
  const hrp = isStake
    ? mainnet ? 'stake' : 'stake_test'
    : mainnet ? 'addr' : 'addr_test';
  return bech32Encode(hrp, raw);
}

/** Read the ed25519 public key (COSE_Key map key -2) as hex. */
function publicKeyHexFromCoseKey(coseKeyHex: string): string | null {
  let bytes: Uint8Array;
  try {
    bytes = hexToBytes(coseKeyHex);
  } catch {
    return null;
  }
  const decoded = cborDecode(bytes);
  if (!(decoded instanceof Map)) return null;
  const x = decoded.get(-2);
  return x instanceof Uint8Array ? bytesToHex(x) : null;
}

export class CardanoConnector implements WalletConnector {
  readonly chain = 'cardano' as const;

  #api: Cip30Api | null = null;
  /** The CIP-30 hex address we sign against (signData's first arg). */
  #addressHex: string | null = null;

  async available(): Promise<WalletInfo[]> {
    const win = getWindow();
    if (!win) return [];
    return discover(win).map(({ id, entry }) => ({
      id,
      name: entry.name ?? WALLET_NAMES[id] ?? id,
      chain: this.chain,
      icon: entry.icon,
      installed: true,
    }));
  }

  /** Enable the chosen CIP-30 wallet and return its signing account. */
  async connect(walletId?: string): Promise<Account> {
    const win = getWindow();
    if (!win) throw new Error('cardano: no window — connectors are browser-only');

    const entries = discover(win);
    if (entries.length === 0) throw new Error('cardano: no injected CIP-30 wallet found');

    const chosen = walletId != null ? entries.find((e) => e.id === walletId) : entries[0];
    if (!chosen) throw new Error(`cardano: wallet '${walletId}' not found`);

    const api = await chosen.entry.enable();

    // Prefer a used payment address; fall back to change, then reward/stake.
    let addressHex: string | undefined;
    const used = await api.getUsedAddresses().catch(() => [] as string[]);
    addressHex = used[0];
    if (addressHex == null && api.getChangeAddress) {
      addressHex = await api.getChangeAddress().catch(() => undefined);
    }
    if (addressHex == null) {
      const reward = await api.getRewardAddresses().catch(() => [] as string[]);
      addressHex = reward[0];
    }
    if (addressHex == null) {
      throw new Error('cardano: wallet returned no usable address');
    }

    const address = hexAddressToBech32(addressHex);
    if (address == null) throw new Error('cardano: could not render address to bech32');

    this.#api = api;
    this.#addressHex = addressHex;
    return { chain: this.chain, address, walletId: chosen.id };
  }

  /**
   * Render the CAIP-122 message and have the wallet sign its UTF-8 bytes via
   * CIP-8 `signData`. Produces an `ed25519-cardano` proof whose COSE_Sign1
   * {@link import('./verify.js').verifyCardano} checks, binding blake2b-224 of
   * the COSE_Key public key to the bech32 address.
   */
  async signLogin(account: Account, challenge: LoginChallenge): Promise<SignedProof> {
    if (!this.#api || this.#addressHex == null) {
      throw new Error('cardano: not connected — call connect() first');
    }

    const message = buildSiwxMessage({
      challenge,
      address: account.address,
      chain: this.chain,
    });

    const payloadHex = bytesToHex(utf8ToBytes(message));
    const { signature, key } = await this.#api.signData(this.#addressHex, payloadHex);

    const publicKey = publicKeyHexFromCoseKey(key);
    if (publicKey == null) {
      throw new Error('cardano: COSE_Key has no ed25519 public key (-2)');
    }

    return {
      chain: this.chain,
      scheme: 'ed25519-cardano',
      address: account.address,
      publicKey,
      message,
      signature,
      extra: { coseKey: key },
    };
  }

  async disconnect(): Promise<void> {
    this.#api = null;
    this.#addressHex = null;
  }
}
