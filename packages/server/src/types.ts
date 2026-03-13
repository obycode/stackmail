import type { EncryptedMail } from '@mailslot/crypto';

export type { EncryptedMail };

// ─── Wire types (over-the-network) ───────────────────────────────────────────

/**
 * Returned to sender before they compose a message.
 * Contains everything needed to encrypt the payload and build the payment proof.
 */
export interface PaymentInfo {
  paymentId: string;
  /** SHA-256 hash of R — sender embeds this in their StackFlow state update */
  hashedSecret: string;
  /** Recipient's compressed secp256k1 pubkey (33 bytes hex) — sender encrypts to this */
  recipientPublicKey: string;
  /** Total amount sender must pay, in token base units */
  amount: string;
  /** Server's cut */
  fee: string;
  /** What recipient receives (amount - fee) */
  recipientAmount: string;
  /** Server's StackFlow node URL, for the indirect x402 payment */
  stackflowNodeUrl: string;
  /** Server's STX address */
  serverAddress: string;
  /** Unix ms — this paymentId expires and cannot be reused after this */
  expiresAt: number;
}

/**
 * Pending outgoing StackFlow state update from server → recipient,
 * locked by the same hashedSecret. Sent to recipient when they poll,
 * so they can verify the payment before revealing R.
 */
export interface PendingPayment {
  /** Full StackFlow state proof, signed by server */
  stateProof: Record<string, unknown>;
  /** Amount offered to recipient */
  amount: string;
  hashedSecret: string;
}

export type MessageDeliveryState = 'ready' | 'previewed' | 'deferred' | 'settled' | 'cancelled';
export type DeferredReason = 'no-recipient-tap' | 'insufficient-recipient-liquidity';

/** Inbox listing entry — no body, no secret */
export interface InboxEntry {
  id: string;
  from: string;
  sentAt: number;
  /** Payment offered to recipient if they claim */
  amount: string;
  claimed: boolean;
}

/** Full message returned after claiming */
export interface MailMessage {
  id: string;
  from: string;
  to: string;
  sentAt: number;
  amount: string;
  fee: string;
  paymentId: string;
  /** Encrypted payload — recipient decrypts this to get subject, body, and secret */
  encryptedPayload: EncryptedMail;
}

// ─── DB / internal ───────────────────────────────────────────────────────────

export interface StoredMessage {
  id: string;
  from: string;
  to: string;
  sentAt: number;
  amount: string;
  fee: string;
  paymentId: string;
  hashedSecret: string;
  encryptedPayload: EncryptedMail;
  /** Server's signed outgoing state update to recipient, created at receipt time */
  pendingPayment: PendingPayment | null;
  deliveryState: MessageDeliveryState;
  deferredReason?: DeferredReason;
  deferredUntil?: number;
  previewedAt?: number;
  cancelledAt?: number;
  claimed: boolean;
  claimedAt?: number;
  paymentSettled: boolean;
}

export interface SettlementRecord {
  messageId: string;
  paymentId: string;
  recipientAddr: string;
  hashedSecret: string;
  secret: string;
  pendingPayment: PendingPayment | null;
  settledAt: number;
}

export interface InboxQuery {
  limit?: number;
  before?: number;
  includeClaimed?: boolean;
}

// ─── Config ──────────────────────────────────────────────────────────────────

export interface Config {
  host: string;
  port: number;
  dbBackend: 'sqlite' | 'postgres';
  dbFile: string;
  dbUrl?: string;
  maxEncryptedBytes: number;
  authTimestampTtlMs: number;
  authAudience: string;
  /** @deprecated kept for payment-info response compatibility */
  stackflowNodeUrl: string;
  /** Standard principal used to verify server signatures (derived from private key by default) */
  serverStxAddress: string;
  /** Hex private key used by the reservoir to sign outgoing state updates */
  serverPrivateKey: string;
  /** StackFlow contract ID this server operates (e.g. SP...stackflow-sbtc-0-6-0) */
  sfContractId: string;
  /** Reservoir contract principal (e.g. SP....sm-reservoir) for tap onboarding */
  reservoirContractId: string;
  /** Stacks chain ID: 1 = mainnet, 2147483648 = testnet/devnet */
  chainId: number;
  /** Startup default for runtime-configurable message price */
  messagePriceSats: string;
  /** Startup default for runtime-configurable fee */
  minFeeSats: string;
  /** Max unclaimed messages allowed from a single sender to a single recipient */
  maxPendingPerSender: number;
  /** Max total unclaimed messages allowed for a single recipient inbox */
  maxPendingPerRecipient: number;
  /** Max deferred sender-paid messages allowed from a single sender to one recipient */
  maxDeferredPerSender: number;
  /** Max deferred sender-paid messages queued for a single recipient */
  maxDeferredPerRecipient: number;
  /** Max total deferred sender-paid messages queued on this server */
  maxDeferredGlobal: number;
  /** How long deferred sender-paid messages remain retryable */
  deferredMessageTtlMs: number;
  /** Max additional receive liquidity the server will offer to a single tap */
  maxBorrowPerTap: string;
  inboxSessionTtlMs: number;
  allowedOrigins: string[];
  rateLimitWindowMs: number;
  rateLimitMax: number;
  rateLimitAuthMax: number;
  rateLimitSendMax: number;
  rateLimitAdminMax: number;
  enableBrowserDecryptKey: boolean;
  disputeWebhookToken?: string;
}

export interface RuntimeSettings {
  messagePriceSats: string;
  minFeeSats: string;
  maxPendingPerSender: number;
  maxPendingPerRecipient: number;
  maxDeferredPerSender: number;
  maxDeferredPerRecipient: number;
  maxDeferredGlobal: number;
  deferredMessageTtlMs: number;
  maxBorrowPerTap: string;
}

export function runtimeSettingsFromConfig(config: Pick<
  Config,
  | 'messagePriceSats'
  | 'minFeeSats'
  | 'maxPendingPerSender'
  | 'maxPendingPerRecipient'
  | 'maxDeferredPerSender'
  | 'maxDeferredPerRecipient'
  | 'maxDeferredGlobal'
  | 'deferredMessageTtlMs'
  | 'maxBorrowPerTap'
>): RuntimeSettings {
  return {
    messagePriceSats: config.messagePriceSats,
    minFeeSats: config.minFeeSats,
    maxPendingPerSender: config.maxPendingPerSender,
    maxPendingPerRecipient: config.maxPendingPerRecipient,
    maxDeferredPerSender: config.maxDeferredPerSender,
    maxDeferredPerRecipient: config.maxDeferredPerRecipient,
    maxDeferredGlobal: config.maxDeferredGlobal,
    deferredMessageTtlMs: config.deferredMessageTtlMs,
    maxBorrowPerTap: config.maxBorrowPerTap,
  };
}

export function loadConfig(): Config {
  const env = (name: string, legacy?: string): string | undefined => process.env[name] ?? (legacy ? process.env[legacy] : undefined);
  const network = (env('MAILSLOT_STACKS_NETWORK', 'STACKMAIL_STACKS_NETWORK') ?? 'mainnet').toLowerCase();
  const chainId = network === 'mainnet' ? 1 : 2147483648;
  return {
    host: env('MAILSLOT_HOST', 'STACKMAIL_HOST') ?? '0.0.0.0',
    port: parseInt(env('MAILSLOT_PORT', 'STACKMAIL_PORT') ?? '8800', 10),
    dbBackend: (env('MAILSLOT_DB_BACKEND', 'STACKMAIL_DB_BACKEND') ?? 'sqlite') as 'sqlite' | 'postgres',
    dbFile: env('MAILSLOT_DB_FILE', 'STACKMAIL_DB_FILE') ?? './data/mailslot.db',
    dbUrl: env('MAILSLOT_DB_URL', 'STACKMAIL_DB_URL'),
    maxEncryptedBytes: parseInt(env('MAILSLOT_MAX_ENCRYPTED_BYTES', 'STACKMAIL_MAX_ENCRYPTED_BYTES') ?? '65536', 10),
    authTimestampTtlMs: parseInt(env('MAILSLOT_AUTH_TIMESTAMP_TTL_MS', 'STACKMAIL_AUTH_TIMESTAMP_TTL_MS') ?? '300000', 10),
    authAudience: env('MAILSLOT_AUTH_AUDIENCE', 'STACKMAIL_AUTH_AUDIENCE') ?? '',
    stackflowNodeUrl: env('MAILSLOT_STACKFLOW_NODE_URL', 'STACKMAIL_STACKFLOW_NODE_URL') ?? '',
    serverStxAddress: env('MAILSLOT_SERVER_STX_ADDRESS', 'STACKMAIL_SERVER_STX_ADDRESS') ?? '',
    serverPrivateKey: env('MAILSLOT_SERVER_PRIVATE_KEY', 'STACKMAIL_SERVER_PRIVATE_KEY') ?? '',
    sfContractId: env('MAILSLOT_SF_CONTRACT_ID', 'STACKMAIL_SF_CONTRACT_ID') ?? '',
    reservoirContractId: env('MAILSLOT_RESERVOIR_CONTRACT_ID', 'STACKMAIL_RESERVOIR_CONTRACT_ID') ?? '',
    chainId,
    messagePriceSats: env('MAILSLOT_MESSAGE_PRICE_SATS', 'STACKMAIL_MESSAGE_PRICE_SATS') ?? '1000',
    minFeeSats: env('MAILSLOT_MIN_FEE_SATS', 'STACKMAIL_MIN_FEE_SATS') ?? '100',
    maxPendingPerSender: parseInt(env('MAILSLOT_MAX_PENDING_PER_SENDER', 'STACKMAIL_MAX_PENDING_PER_SENDER') ?? '5', 10),
    maxPendingPerRecipient: parseInt(env('MAILSLOT_MAX_PENDING_PER_RECIPIENT', 'STACKMAIL_MAX_PENDING_PER_RECIPIENT') ?? '20', 10),
    maxDeferredPerSender: parseInt(env('MAILSLOT_MAX_DEFERRED_PER_SENDER', 'STACKMAIL_MAX_DEFERRED_PER_SENDER') ?? '5', 10),
    maxDeferredPerRecipient: parseInt(env('MAILSLOT_MAX_DEFERRED_PER_RECIPIENT', 'STACKMAIL_MAX_DEFERRED_PER_RECIPIENT') ?? '20', 10),
    maxDeferredGlobal: parseInt(env('MAILSLOT_MAX_DEFERRED_GLOBAL', 'STACKMAIL_MAX_DEFERRED_GLOBAL') ?? '200', 10),
    deferredMessageTtlMs: parseInt(env('MAILSLOT_DEFERRED_MESSAGE_TTL_MS', 'STACKMAIL_DEFERRED_MESSAGE_TTL_MS') ?? '86400000', 10),
    maxBorrowPerTap: env('MAILSLOT_MAX_BORROW_PER_TAP', 'STACKMAIL_MAX_BORROW_PER_TAP') ?? '100000',
    inboxSessionTtlMs: parseInt(env('MAILSLOT_INBOX_SESSION_TTL_MS', 'STACKMAIL_INBOX_SESSION_TTL_MS') ?? '300000', 10),
    allowedOrigins: (env('MAILSLOT_ALLOWED_ORIGINS', 'STACKMAIL_ALLOWED_ORIGINS') ?? '')
      .split(',')
      .map(value => value.trim())
      .filter(Boolean),
    rateLimitWindowMs: parseInt(env('MAILSLOT_RATE_LIMIT_WINDOW_MS', 'STACKMAIL_RATE_LIMIT_WINDOW_MS') ?? '60000', 10),
    rateLimitMax: parseInt(env('MAILSLOT_RATE_LIMIT_MAX', 'STACKMAIL_RATE_LIMIT_MAX') ?? '120', 10),
    rateLimitAuthMax: parseInt(env('MAILSLOT_RATE_LIMIT_AUTH_MAX', 'STACKMAIL_RATE_LIMIT_AUTH_MAX') ?? '60', 10),
    rateLimitSendMax: parseInt(env('MAILSLOT_RATE_LIMIT_SEND_MAX', 'STACKMAIL_RATE_LIMIT_SEND_MAX') ?? '20', 10),
    rateLimitAdminMax: parseInt(env('MAILSLOT_RATE_LIMIT_ADMIN_MAX', 'STACKMAIL_RATE_LIMIT_ADMIN_MAX') ?? '10', 10),
    enableBrowserDecryptKey: (env('MAILSLOT_ENABLE_BROWSER_DECRYPT_KEY', 'STACKMAIL_ENABLE_BROWSER_DECRYPT_KEY') ?? 'false').toLowerCase() === 'true',
    disputeWebhookToken: env('MAILSLOT_DISPUTE_WEBHOOK_TOKEN', 'STACKMAIL_DISPUTE_WEBHOOK_TOKEN'),
  };
}
