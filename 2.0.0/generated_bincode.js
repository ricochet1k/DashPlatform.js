import {
  Bool, Bytes, Enum, VariantDiscriminant, FixedBytes, Lazy, Struct, StructTuple,
  Int128, Int16, Int32, Int64, Int8, Uint128, Uint16, Uint32, Uint64, Uint8, Float64,
  VarInt, VarUint, Vec, Tuple, Map, Option, String, Nothing, Range, NotSignable,
  SocketAddr,
} from "../bincode.ts"
import { Transaction } from "../bincode_types.ts";
export const Hash = Bytes; //FixedBytes(32)

/** @type {*} */
export const Value = Lazy("Value", () => REAL_Value);

export const BinaryData = StructTuple("BinaryData",
  Bytes,
);

export const BlockHeight = VarUint

export const BlockHeightInterval = VarUint

export const Credits = VarUint

export const DefinitionName = String

export const DerivationEncryptionKeyIndex = VarUint

export const DocumentName = String

export const EpochIndex = VarUint

export const EpochInterval = VarUint

export const GroupContractPosition = VarUint

export const GroupMemberPower = VarUint

export const GroupRequiredPower = VarUint

export const Hash256 = FixedBytes(32)

export const IdentifierBytes32 = StructTuple("IdentifierBytes32",
  FixedBytes(32),
);

export const IdentityNonce = VarUint

export const KeyID = VarUint

/**
 * allow non_camel_case_types
 * repr u8
 */
export const KeyType = Enum("KeyType", /** @type {const} */ ({
  /** default */
  ECDSA_SECP256K1: [],
  BLS12_381: [],
  ECDSA_HASH160: [],
  BIP13_SCRIPT_HASH: [],
  EDDSA_25519_HASH160: [],
}))

/** repr u8 */
export const Pooling = Enum("Pooling", /** @type {const} */ ({
  /** default */
  Never: [],
  IfAvailable: [],
  Standard: [],
}))

/** repr u8 */
export const Purpose = Enum("Purpose", /** @type {const} */ ({
  /**
   * at least one authentication key must be registered for all security levels
   * default
   */
  AUTHENTICATION: [],
  /** this key cannot be used for signing documents */
  ENCRYPTION: [],
  /** this key cannot be used for signing documents */
  DECRYPTION: [],
  /** this key is used to sign credit transfer and withdrawal state transitions */
  TRANSFER: [],
  /** this key cannot be used for signing documents */
  SYSTEM: [],
  /** this key cannot be used for signing documents */
  VOTING: [],
  /** this key is used to prove ownership of a masternode or evonode */
  OWNER: [],
}))

// !ENCODE
/** "Raw" instant lock for serialization */
export const RawInstantLockProof = Struct("RawInstantLockProof", {
  instant_lock: BinaryData,
  transaction: BinaryData,
  output_index: VarUint,
});

export const RecipientKeyIndex = VarUint

export const Revision = VarUint

export const RootEncryptionKeyIndex = VarUint

// !ENCODE
/**
 * An owned, growable script.
 * 
 *  `ScriptBuf` is the most common script type that has the ownership over the contents of the
 *  script. It has a close relationship with its borrowed counterpart, [`Script`].
 * 
 *  Just as other similar types, this implements [`Deref`], so [deref coercions] apply. Also note
 *  that all the safety/validity restrictions that apply to [`Script`] apply to `ScriptBuf` as well.
 * 
 *  [deref coercions]: https://doc.rust-lang.org/std/ops/trait.Deref.html#more-on-deref-coercion
 */
export const ScriptBuf = StructTuple("ScriptBuf",
  Bytes,
);

/** repr u8 */
export const SecurityLevel = Enum("SecurityLevel", /** @type {const} */ ({
  MASTER: [],
  CRITICAL: [],
  /** default */
  HIGH: [],
  MEDIUM: [],
}))

export const SenderKeyIndex = VarUint

export const SharedEncryptedNote = Tuple(SenderKeyIndex, RecipientKeyIndex, Bytes)

/**
 * The Storage Key requirements
 * repr u8
 */
export const StorageKeyRequirements = Enum("StorageKeyRequirements", /** @type {const} */ ({
  Unique: [],
  Multiple: [],
  MultipleReferenceToLatest: [],
}))

export const TimestampMillis = VarUint

export const TimestampMillisInterval = VarUint

export const TokenAmount = VarUint

export const TokenConfigurationLocalizationV0 = Struct("TokenConfigurationLocalizationV0", {
  should_capitalize: Bool,
  singular_form: String,
  plural_form: String,
});

export const TokenContractPosition = VarUint

/**
 * Represents the type of token distribution.
 * 
 *  - `PreProgrammed`: A scheduled distribution with predefined rules.
 *  - `Perpetual`: A continuous or recurring distribution.
 */
export const TokenDistributionType = Enum("TokenDistributionType", /** @type {const} */ ({
  /**
   * A pre-programmed distribution scheduled for a specific time.
   * default
   */
  PreProgrammed: [],
  /** A perpetual distribution that occurs at regular intervals. */
  Perpetual: [],
}))

export const TokenEmergencyAction = Enum("TokenEmergencyAction", /** @type {const} */ ({
  /** default */
  Pause: [],
  Resume: [],
}))

/**
 * The rules for keeping a ledger as documents of token events.
 *  Config update, Destroying Frozen Funds, Emergency Action,
 *  Pre Programmed Token Release always require an entry to the ledger
 */
export const TokenKeepsHistoryRulesV0 = Struct("TokenKeepsHistoryRulesV0", {
  /** Whether transfer history is recorded. */
  keeps_transfer_history: Bool,
  /** Whether freezing history is recorded. */
  keeps_freezing_history: Bool,
  /** Whether minting history is recorded. */
  keeps_minting_history: Bool,
  /** Whether burning history is recorded. */
  keeps_burning_history: Bool,
});

// !ENCODE
/** A transaction output, which defines new coins to be created from old ones. */
export const TxOut = Struct("TxOut", {
  /** The value of the output, in satoshis. */
  value: VarUint,
  /** The script which must be satisfied for the output to be spent. */
  script_pubkey: ScriptBuf,
});

// !ENCODE
/** A dash transaction hash/transaction ID. */
export const Txid = StructTuple("Txid",
  Hash,
);

export const UserFeeIncrease = VarUint

export const ValueMap = Vec(Tuple(Value, Value))

// !ENCODE
/**
 * An Asset Lock payload. This is contained as the payload of an asset lock special transaction.
 *  The Asset Lock Special transaction and this payload is described in the Asset Lock DIP2X
 *  (todo:update this).
 *  An Asset Lock can fund multiple Identity registrations or top ups.
 *  The Asset Lock payload credit outputs field contains a vector of TxOuts.
 *  Each TxOut refers to a funding of an Identity.
 */
export const AssetLockPayload = Struct("AssetLockPayload", {
  version: Uint8,
  credit_outputs: Vec(TxOut),
});

export const DashcoreScript = ScriptBuf

export const DataContractConfigV0 = Struct("DataContractConfigV0", {
  /**
   * Can the contract ever be deleted. If the contract is deleted, so should be all
   *  documents associated with it. TODO: There should also be a way to "stop" the contract -
   *  contract and documents are kept in the system, but no new documents can be added to it
   */
  can_be_deleted: Bool,
  /**
   * Is the contract mutable. Means that the document definitions can be changed or new
   *  document definitions can be added to the contract
   */
  readonly: Bool,
  /** Does the contract keep history when the contract itself changes */
  keeps_history: Bool,
  /**
   * Do documents in the contract keep history. This is a default for all documents in
   *  the contract, but can be overridden by the document itself
   */
  documents_keep_history_contract_default: Bool,
  /**
   * Are documents in the contract mutable? This specifies whether the documents can be
   *  changed. This is a default for all document types in the contract, but can be
   *  overridden by the document type config.
   */
  documents_mutable_contract_default: Bool,
  /**
   * Can documents in the contract be deleted? This specifies whether the documents can be
   *  deleted. This is a default for all document types in the contract, but can be
   *  overridden by the document types itself.
   */
  documents_can_be_deleted_contract_default: Bool,
  /** Encryption key storage requirements */
  requires_identity_encryption_bounded_key: Option(StorageKeyRequirements),
  /** Decryption key storage requirements */
  requires_identity_decryption_bounded_key: Option(StorageKeyRequirements),
});

export const DataContractConfigV1 = Struct("DataContractConfigV1", {
  /**
   * Can the contract ever be deleted. If the contract is deleted, so should be all
   *  documents associated with it. TODO: There should also be a way to "stop" the contract -
   *  contract and documents are kept in the system, but no new documents can be added to it
   */
  can_be_deleted: Bool,
  /**
   * Is the contract mutable. Means that the document definitions can be changed or new
   *  document definitions can be added to the contract
   */
  readonly: Bool,
  /** Does the contract keep history when the contract itself changes */
  keeps_history: Bool,
  /**
   * Do documents in the contract keep history. This is a default for all documents in
   *  the contract, but can be overridden by the document itself
   */
  documents_keep_history_contract_default: Bool,
  /**
   * Are documents in the contract mutable? This specifies whether the documents can be
   *  changed. This is a default for all document types in the contract, but can be
   *  overridden by the document type config.
   */
  documents_mutable_contract_default: Bool,
  /**
   * Can documents in the contract be deleted? This specifies whether the documents can be
   *  deleted. This is a default for all document types in the contract, but can be
   *  overridden by the document types itself.
   */
  documents_can_be_deleted_contract_default: Bool,
  /** Encryption key storage requirements */
  requires_identity_encryption_bounded_key: Option(StorageKeyRequirements),
  /** Decryption key storage requirements */
  requires_identity_decryption_bounded_key: Option(StorageKeyRequirements),
  /** Use sized integer Rust types for `integer` property type based on validation rules */
  sized_integer_types: Bool,
});

// !ENCODE
export const DistributionFunction = Enum("DistributionFunction", /** @type {const} */ ({
  /**
   * Emits a constant (fixed) number of tokens for every period.
   * 
   *  # Formula
   *  For any period `x`, the emitted tokens are:
   * 
   *  ```text
   *  f(x) = n
   *  ```
   * 
   *  # Use Case
   *  - When a predictable, unchanging reward is desired.
   *  - Simplicity and stable emissions.
   * 
   *  # Example
   *  - If `n = 5` tokens per block, then after 3 blocks the total emission is 15 tokens.
   */
  FixedAmount: {
    amount: TokenAmount,
  },
  /**
   * Emits a random number of tokens within a specified range.
   * 
   *  # Description
   *  - This function selects a **random** token emission amount between `min` and `max`.
   *  - The value is drawn **uniformly** between the bounds.
   *  - The randomness uses a Pseudo Random Function (PRF) from x.
   * 
   *  # Formula
   *  For any period `x`, the emitted tokens follow:
   * 
   *  ```text
   *  f(x) ∈ [min, max]
   *  ```
   * 
   *  # Parameters
   *  - `min`: The **minimum** possible number of tokens emitted.
   *  - `max`: The **maximum** possible number of tokens emitted.
   * 
   *  # Use Cases
   *  - **Stochastic Rewards**: Introduces randomness into rewards to incentivize unpredictability.
   *  - **Lottery-Based Systems**: Used for randomized emissions, such as block rewards with probabilistic payouts.
   * 
   *  # Example
   *  Suppose a system emits **between 10 and 100 tokens per period**.
   * 
   *  ```text
   *  Random { min: 10, max: 100 }
   *  ```
   * 
   *  | Period (x) | Emitted Tokens (Random) |
   *  |------------|------------------------|
   *  | 1          | 27                     |
   *  | 2          | 94                     |
   *  | 3          | 63                     |
   *  | 4          | 12                     |
   * 
   *  - Each period, the function emits a **random number of tokens** between `min = 10` and `max = 100`.
   *  - Over time, the **average reward trends toward the midpoint** `(min + max) / 2`.
   * 
   *  # Constraints
   *  - **`min` must be ≤ `max`**, otherwise the function is invalid.
   *  - If `min == max`, this behaves like a `FixedAmount` function with a constant emission.
   */
  Random: {
    min: TokenAmount,
    max: TokenAmount,
  },
  /**
   * Emits tokens that decrease in discrete steps at fixed intervals.
   * 
   *  # Formula
   *  For a given period `x`, the emission is calculated as:
   * 
   *  ```text
   *  f(x) = n * (1 - (decrease_per_interval_numerator / decrease_per_interval_denominator))^((x - s) / step_count)
   *  ```
   * 
   *  # Parameters
   *  - `step_count`: The number of periods between each step.
   *  - `decrease_per_interval_numerator` and `decrease_per_interval_denominator`: Define the reduction factor per step.
   *  - `s`: Optional start period offset (e.g., start block or time). If not provided, the contract creation start is used.
   *  - `n`: The initial token emission.
   *  - `min_value`: Optional minimum emission value.
   * 
   *  # Use Case
   *  - Modeling reward systems similar to Bitcoin or Dash Core.
   *  - Encouraging early participation by providing higher rewards initially.
   * 
   *  # Example
   *  - Bitcoin-style: 50% reduction every 210,000 blocks.
   *  - Dash-style: Approximately a 7% reduction every 210,000 blocks.
   */
  StepDecreasingAmount: {
    step_count: VarUint,
    decrease_per_interval_numerator: VarUint,
    decrease_per_interval_denominator: VarUint,
    s: Option(VarUint),
    n: TokenAmount,
    min_value: Option(VarUint),
  },
  /**
   * Emits tokens in fixed amounts for predefined intervals (steps).
   * 
   *  # Details
   *  - Within each step, the emission remains constant.
   *  - The keys in the `BTreeMap` represent the starting period for each interval,
   *    and the corresponding values are the fixed token amounts to emit during that interval.
   * 
   *  # Use Case
   *  - Adjusting rewards at specific milestones or time intervals.
   * 
   *  # Example
   *  - Emit 100 tokens per block for the first 1,000 blocks, then 50 tokens per block thereafter.
   */
  Stepwise: [Map(VarUint, TokenAmount)],
  /**
   * Emits tokens following a linear function that can increase or decrease over time
   *  with fractional precision.
   * 
   *  # Formula
   *  The emission at period `x` is given by:
   * 
   *  ```text
   *  f(x) = (a * (x - start_moment) / d) + starting_amount
   *  ```
   * 
   *  # Parameters
   *  - `a`: The slope numerator; determines the rate of change.
   *  - `d`: The slope divisor; together with `a` controls the fractional rate.
   *  - `s`: Optional start period offset. If not set, the contract creation start is assumed.
   *  - `b`: The initial token emission (offset).
   *  - `min_value` / `max_value`: Optional bounds to clamp the emission.
   * 
   *  # Details
   *  - If `a > 0`, emissions increase over time.
   *  - If `a < 0`, emissions decrease over time.
   * 
   *  # Behavior
   *  - **If `a > 0`**, emissions increase linearly over time.
   *  - **If `a < 0`**, emissions decrease linearly over time.
   *  - **If `a = 0`**, emissions remain constant at `b`.
   * 
   *  # Use Cases
   *  - **Predictable Inflation or Deflation:** A simple mechanism to adjust token supply dynamically.
   *  - **Long-Term Incentive Structures:** Ensures steady and measurable growth or reduction of rewards.
   *  - **Decaying Emissions:** Can be used to gradually taper off token rewards over time.
   *  - **Sustained Growth Models:** Encourages prolonged engagement by steadily increasing rewards.
   * 
   *  # Examples
   * 
   *  ## **1️⃣ Increasing Linear Emission (`a > 0`)**
   *  - Tokens increase by **1 token per block** starting from 10.
   * 
   *  ```text
   *  f(x) = (1 * (x - 0) / 1) + 10
   *  ```
   * 
   *  | Block (x) | f(x) (Tokens) |
   *  |-----------|---------------|
   *  | 0         | 10            |
   *  | 1         | 11            |
   *  | 2         | 12            |
   *  | 3         | 13            |
   * 
   *  **Use Case:** Encourages continued participation by providing increasing rewards over time.
   * 
   *  ---
   * 
   *  ## **2️⃣ Decreasing Linear Emission (`a < 0`)**
   *  - Tokens **start at 100 and decrease by 2 per period**.
   * 
   *  ```text
   *  f(x) = (-2 * (x - 0) / 1) + 100
   *  ```
   * 
   *  | Block (x) | f(x) (Tokens) |
   *  |-----------|---------------|
   *  | 0         | 100           |
   *  | 1         | 98            |
   *  | 2         | 96            |
   *  | 3         | 94            |
   * 
   *  **Use Case:** Suitable for deflationary models where rewards need to decrease over time.
   * 
   *  ---
   * 
   *  ## **3️⃣ Emission with a Delayed Start (`s > 0`)**
   *  - **No emissions before `x = s`** (e.g., rewards start at block `10`).
   * 
   *  ```text
   *  f(x) = (5 * (x - 10) / 1) + 50
   *  ```
   * 
   *  | Block (x) | f(x) (Tokens) |
   *  |-----------|---------------|
   *  | 9         | 50 (no change)|
   *  | 10        | 50            |
   *  | 11        | 55            |
   *  | 12        | 60            |
   * 
   *  **Use Case:** Useful when rewards should only begin at a specific milestone.
   * 
   *  ---
   * 
   *  ## **4️⃣ Clamping Emissions with `min_value` and `max_value`**
   *  - **Start at 50, increase by 2, but never exceed 60.**
   * 
   *  ```text
   *  f(x) = (2 * (x - 0) / 1) + 50
   *  ```
   * 
   *  | Block (x) | f(x) (Tokens) |
   *  |-----------|---------------|
   *  | 0         | 50            |
   *  | 1         | 52            |
   *  | 2         | 54            |
   *  | 5         | 60 (max cap)  |
   * 
   *  **Use Case:** Prevents runaway inflation by limiting the emission range.
   * 
   *  ---
   * 
   *  # Summary
   *  - **Increasing rewards (`a > 0`)**: Encourages longer participation.
   *  - **Decreasing rewards (`a < 0`)**: Supports controlled deflation.
   *  - **Delayed start (`s > 0`)**: Ensures rewards only begin at a specific point.
   *  - **Clamping (`min_value`, `max_value`)**: Maintains controlled emission boundaries.
   */
  Linear: {
    a: VarInt,
    d: VarUint,
    start_step: Option(VarUint),
    starting_amount: TokenAmount,
    min_value: Option(VarUint),
    max_value: Option(VarUint),
  },
  /**
   * Emits tokens following a polynomial curve with integer arithmetic.
   * 
   *  # Formula
   *  The emission at period `x` is given by:
   * 
   *  ```text
   *  f(x) = (a * (x - s + o)^(m/n)) / d + b
   *  ```
   * 
   *  # Parameters
   *  - `a`: Scaling factor for the polynomial term.
   *  - `m` and `n`: Together specify the exponent as a rational number (allowing non-integer exponents).
   *  - `d`: A divisor for scaling.
   *  - `s`: Optional start period offset. If not provided, the contract creation start is used.
   *  - `o`: An offset for the polynomial function, this is useful if s is in None,
   *  - `b`: An offset added to the computed value.
   *  - `min_value` / `max_value`: Optional bounds to constrain the emission.
   * 
   *  # Behavior & Use Cases
   *  The polynomial function's behavior depends on the values of `a` (scaling factor) and `m` (exponent numerator).
   * 
   *  ## **1️⃣ `a > 0`, `m > 0` (Increasing Polynomial Growth)**
   *  - **Behavior**: Emissions **increase at an accelerating rate** over time.
   *  - **Use Case**: Suitable for models where incentives start small and grow over time (e.g., boosting late-stage participation).
   *  - **Example**:
   *    ```text
   *    f(x) = (2 * (x - s + o)^2) / d + 10
   *    ```
   *    - If `s = 0`, `o = 0`, and `d = 1`, then:
   *      - `f(1) = 12`
   *      - `f(2) = 18`
   *      - `f(3) = 28` (Emissions **accelerate over time**)
   * 
   *  ## **2️⃣ `a > 0`, `m < 0` (Decreasing Polynomial Decay)**
   *  - **Behavior**: Emissions **start high and gradually decline**.
   *  - **Use Case**: Useful for front-loaded incentives where rewards are larger at the beginning and taper off over time.
   *  - **Example**:
   *    ```text
   *    f(x) = (5 * (x - s + o)^(-1)) / d + 10
   *    ```
   *    - If `s = 0`, `o = 0`, and `d = 1`, then:
   *      - `f(1) = 15`
   *      - `f(2) = 12.5`
   *      - `f(3) = 11.67` (Emissions **shrink but never hit zero**)
   * 
   *  ## **3️⃣ `a < 0`, `m > 0` (Inverted Growth → Decreasing Over Time)**
   *  - **Behavior**: Emissions **start large but decrease faster over time**.
   *  - **Use Case**: Suitable for cases where high initial incentives quickly drop off (e.g., limited early rewards).
   *  - **Example**:
   *    ```text
   *    f(x) = (-3 * (x - s + o)^2) / d + 50
   *    ```
   *    - If `s = 0`, `o = 0`, and `d = 1`, then:
   *      - `f(1) = 47`
   *      - `f(2) = 38`
   *      - `f(3) = 23` (Emissions **fall sharply**)
   * 
   *  ## **4️⃣ `a < 0`, `m < 0` (Inverted Decay → Slowing Increase)**
   *  - **Behavior**: Emissions **start low, rise gradually, and then flatten out**.
   *  - **Use Case**: Useful for controlled inflation where rewards increase over time but approach a stable maximum.
   *  - **Example**:
   *    ```text
   *    f(x) = (-10 * (x - s + o)^(-2)) / d + 50
   *    ```
   *    - If `s = 0`, `o = 0`, and `d = 1`, then:
   *      - `f(1) = 40`
   *      - `f(2) = 47.5`
   *      - `f(3) = 48.89` (Growth **slows as it approaches 50**)
   * 
   *  # Summary
   *  - **Positive `a` means increasing emissions**, while **negative `a` means decreasing emissions**.
   *  - **Positive `m` leads to growth**, while **negative `m` leads to decay**.
   *  - The combination of `a` and `m` defines whether emissions accelerate, decay, or remain stable.
   */
  Polynomial: {
    a: VarInt,
    d: VarUint,
    m: VarInt,
    n: VarUint,
    o: VarInt,
    start_moment: Option(VarUint),
    b: TokenAmount,
    min_value: Option(VarUint),
    max_value: Option(VarUint),
  },
  /**
   * Emits tokens following an exponential function.
   * 
   *  # Formula
   *  The emission at period `x` is given by:
   * 
   *  ```text
   *  f(x) = (a * e^(m * (x - s) / n)) / d + c
   *  ```
   * 
   *  # Parameters
   *  - `a`: The scaling factor.
   *  - `m` and `n`: Define the exponent rate (with `m > 0` for growth and `m < 0` for decay).
   *  - `d`: A divisor used to scale the exponential term.
   *  - `s`: Optional start period offset. If not set, the contract creation start is assumed.
   *  - `o`: An offset for the exp function, this is useful if s is in None.
   *  - `c`: An offset added to the result.
   *  - `min_value` / `max_value`: Optional constraints on the emitted tokens.
   * 
   *  # Use Cases
   *  ## **Exponential Growth (`m > 0`):**
   *  - **Incentivized Spending**: Higher emissions over time increase the circulating supply, encouraging users to spend tokens.
   *  - **Progressive Emission Models**: Useful for models where early emissions are low but increase significantly over time.
   *  - **Early-Stage Adoption Strategies**: Helps drive later participation by offering increasing rewards as time progresses.
   * 
   *  ## **Exponential Decay (`m < 0`):**
   *  - **Deflationary Reward Models**: Reduces emissions over time, ensuring token scarcity.
   *  - **Early Participation Incentives**: Encourages early users by distributing more tokens initially and gradually decreasing rewards.
   *  - **Sustainable Emission Models**: Helps manage token supply while preventing runaway inflation.
   * 
   *  # Examples
   *  ## **Example 1: Exponential Growth (`m > 0`)**
   *  - **Use Case**: A staking model where rewards increase over time to encourage long-term participation.
   *  - **Parameters**: `a = 100`, `m = 2`, `n = 50`, `d = 10`, `c = 5`
   *  - **Formula**:
   *    ```text
   *    f(x) = (100 * e^(2 * (x - s) / 50)) / 10 + 5
   *    ```
   *  - **Effect**: Emissions start small but **increase exponentially** over time, rewarding late stakers more than early ones.
   * 
   *  ## **Example 2: Exponential Decay (`m < 0`)**
   *  - **Use Case**: A deflationary model where emissions start high and gradually decrease to ensure scarcity.
   *  - **Parameters**: `a = 500`, `m = -3`, `n = 100`, `d = 20`, `c = 10`
   *  - **Formula**:
   *    ```text
   *    f(x) = (500 * e^(-3 * (x - s) / 100)) / 20 + 10
   *    ```
   *  - **Effect**: Emissions start **high and decay exponentially**, ensuring early participants get larger rewards.
   */
  Exponential: {
    a: VarUint,
    d: VarUint,
    m: VarInt,
    n: VarUint,
    o: VarInt,
    start_moment: Option(VarUint),
    c: TokenAmount,
    min_value: Option(VarUint),
    max_value: Option(VarUint),
  },
  /**
   * Emits tokens following a logarithmic function.
   * 
   *  # Formula
   *  The emission at period `x` is computed as:
   * 
   *  ```text
   *  f(x) = (a * log(m * (x - s + o) / n)) / d + b
   *  ```
   * 
   *  # Parameters
   *  - `a`: Scaling factor for the logarithmic term.
   *  - `d`: A divisor for scaling.
   *  - `m` and `n`: Adjust the input to the logarithm function.
   *  - `s`: Optional start period offset. If not provided, the contract creation start is used.
   *  - `o`: An offset for the log function, this is useful if s is in None.
   *  - `b`: An offset added to the result.
   *  - `min_value` / `max_value`: Optional bounds to ensure the emission remains within limits.
   * 
   *  # Use Case
   *  - **Gradual Growth with a Slowing Rate**: Suitable for reward schedules where the emission
   *    starts at a lower rate, increases quickly at first, but then slows down over time.
   *  - **Predictable Emission Scaling**: Ensures a growing but controlled emission curve that
   *    does not escalate too quickly.
   *  - **Sustainability and Inflation Control**: Helps prevent runaway token supply growth
   *    by ensuring rewards increase at a decreasing rate.
   * 
   *  # Example
   *  - Suppose we want token emissions to start at a low value and grow over time, but at a
   *    **decreasing rate**, ensuring controlled long-term growth.
   * 
   *  - Given the formula:
   *    ```text
   *    f(x) = (a * log(m * (x - s + o) / n)) / d + b
   *    ```
   * 
   *  - Let’s assume the following parameters:
   *    - `a = 100`: Scaling factor.
   *    - `d = 10`: Divisor to control overall scaling.
   *    - `m = 2`, `n = 1`: Adjust the logarithmic input.
   *    - `s = 0`, `o = 1`: Starting conditions.
   *    - `b = 50`: Base amount added.
   * 
   *  - This results in:
   *    ```text
   *    f(x) = (100 * log(2 * (x + 1) / 1)) / 10 + 50
   *    ```
   * 
   *  - **Expected Behavior:**
   *    - At `x = 1`, emission = `f(1) = (100 * log(4)) / 10 + 50 ≈ 82`
   *    - At `x = 10`, emission = `f(10) = (100 * log(22)) / 10 + 50 ≈ 106`
   *    - At `x = 100`, emission = `f(100) = (100 * log(202)) / 10 + 50 ≈ 130`
   * 
   *  - **Observations:**
   *    - The emission **increases** over time, but at a **slowing rate**.
   *    - Early increases are more pronounced, but as `x` grows, the additional reward per
   *      period gets smaller.
   *    - This makes it ideal for long-term, controlled emission models.
   */
  Logarithmic: {
    a: VarInt,
    d: VarUint,
    m: VarUint,
    n: VarUint,
    o: VarInt,
    start_moment: Option(VarUint),
    b: TokenAmount,
    min_value: Option(VarUint),
    max_value: Option(VarUint),
  },
  /**
   * Emits tokens following an inverted logarithmic function.
   * 
   *  # Formula
   *  The emission at period `x` is given by:
   * 
   *  ```text
   *  f(x) = (a * log( n / (m * (x - s + o)) )) / d + b
   *  ```
   * 
   *  # Parameters
   *  - `a`: Scaling factor.
   *  - `d`: Divisor for scaling.
   *  - `m` and `n`: Together control the logarithm argument inversion.
   *  - `o`: Offset applied inside the logarithm.
   *  - `s`: Optional start period offset.
   *  - `b`: Offset added to the computed value.
   *  - `min_value` / `max_value`: Optional boundaries for the emission.
   * 
   *  # Use Case
   *  - **Gradual Decay of Rewards**: Suitable when early adopters should receive higher rewards,
   *    but later participants should receive smaller but still meaningful amounts.
   *  - **Resource Draining / Controlled Burn**: Used when token emissions should drop significantly
   *    at first but slow down over time to preserve capital.
   *  - **Airdrop or Grant System**: Ensures early claimants receive larger distributions, but later
   *    claimants receive diminishing rewards.
   * 
   *  # Example
   *  - Suppose a system starts with **500 tokens per period** and gradually reduces over time:
   * 
   *    ```text
   *    f(x) = (1000 * log(5000 / (5 * (x - 1000)))) / 10 + 10
   *    ```
   * 
   *    Example values:
   * 
   *    | Period (x) | Emission (f(x)) |
   *    |------------|----------------|
   *    | 1000       | 500 tokens      |
   *    | 1500       | 230 tokens      |
   *    | 2000       | 150 tokens      |
   *    | 5000       | 50 tokens       |
   *    | 10,000     | 20 tokens       |
   *    | 50,000     | 10 tokens       |
   * 
   *    - The emission **starts high** and **gradually decreases**, ensuring early adopters receive
   *      more tokens while later participants still get rewards.
   *    - The function **slows down the rate of decrease** over time, preventing emissions from
   *      hitting zero too quickly.
   */
  InvertedLogarithmic: {
    a: VarInt,
    d: VarUint,
    m: VarUint,
    n: VarUint,
    o: VarInt,
    start_moment: Option(VarUint),
    b: TokenAmount,
    min_value: Option(VarUint),
    max_value: Option(VarUint),
  },
}))

export const Identifier = StructTuple("Identifier",
  IdentifierBytes32,
);

/** platform_serialize unversioned */
export const IdentityCreditTransferTransitionV0 = Struct("IdentityCreditTransferTransitionV0", {
  identity_id: Identifier,
  recipient_id: Identifier,
  amount: VarUint,
  nonce: IdentityNonce,
  user_fee_increase: UserFeeIncrease,
  signature_public_key_id: NotSignable(KeyID),
  signature: NotSignable(BinaryData),
});

export const InstantAssetLockProof = RawInstantLockProof

// !ENCODE
/** A reference to a transaction output. */
export const OutPoint = Struct("OutPoint", {
  /** The referenced transaction's txid. */
  txid: Txid,
  /** The index of the referenced output in its transaction's vout. */
  vout: VarUint,
});

export const PrivateEncryptedNote = Tuple(RootEncryptionKeyIndex, DerivationEncryptionKeyIndex, Bytes)

/**
 * A representation of a dynamic value that can handled dynamically
 * non_exhaustive
 */
export const REAL_Value = Enum("Value", /** @type {const} */ ({
  /** A u128 integer */
  U128: [VarUint],
  /** A i128 integer */
  I128: [VarInt],
  /** A u64 integer */
  U64: [VarUint],
  /** A i64 integer */
  I64: [VarInt],
  /** A u32 integer */
  U32: [VarUint],
  /** A i32 integer */
  I32: [VarInt],
  /** A u16 integer */
  U16: [VarUint],
  /** A i16 integer */
  I16: [VarInt],
  /** A u8 integer */
  U8: [Uint8],
  /** A i8 integer */
  I8: [Int8],
  /** Bytes */
  Bytes: [Bytes],
  /** Bytes 20 */
  Bytes20: [FixedBytes(20)],
  /** Bytes 32 */
  Bytes32: [FixedBytes(32)],
  /** Bytes 36 : Useful for outpoints */
  Bytes36: [FixedBytes(36)],
  /** An enumeration of u8 */
  EnumU8: [Bytes],
  /** An enumeration of strings */
  EnumString: [Vec(String)],
  /**
   * Identifier
   *  The identifier is very similar to bytes, however it is serialized to Base58 when converted
   *  to a JSON Value
   */
  Identifier: [Hash256],
  /** A float */
  Float: [Float64],
  /** A string */
  Text: [String],
  /** A boolean */
  Bool: [Bool],
  /** Null */
  Null: [],
  /** An array */
  Array: [Vec(Value)],
  /** A map */
  Map: [ValueMap],
}))

/**
 * A resource votes is a votes determining what we should do with a contested resource.
 *  For example Alice and Bob both want the username "Malaka"
 *  Some would vote for Alice to get it by putting in her Identifier.
 *  Some would vote for Bob to get it by putting in Bob's Identifier.
 *  Let's say someone voted, but is now not quite sure of their votes, they can abstain.
 *  Lock is there to signal that the shared resource should be given to no one.
 *  In this case Malaka might have a bad connotation in Greek, hence some might votes to Lock
 *  the name.
 */
export const ResourceVoteChoice = Enum("ResourceVoteChoice", /** @type {const} */ ({
  TowardsIdentity: [Identifier],
  /** default */
  Abstain: [],
  Lock: [],
}))

export const RewardDistributionType = Enum("RewardDistributionType", /** @type {const} */ ({
  /**
   * An amount of tokens is emitted every n blocks.
   *  The start and end are included if set.
   *  If start is not set then it will start at the height of the block when the data contract
   *  is registered.
   */
  BlockBasedDistribution: {
    interval: BlockHeightInterval,
    function: DistributionFunction,
  },
  /**
   * An amount of tokens is emitted every amount of time given.
   *  The start and end are included if set.
   *  If start is not set then it will start at the time of the block when the data contract
   *  is registered.
   */
  TimeBasedDistribution: {
    interval: TimestampMillisInterval,
    function: DistributionFunction,
  },
  /**
   * An amount of tokens is emitted every amount of epochs.
   *  The start and end are included if set.
   *  If start is not set then it will start at the epoch of the block when the data contract
   *  is registered. A distribution would happen at the start of the following epoch, even if it
   *  is just 1 block later.
   */
  EpochBasedDistribution: {
    interval: EpochInterval,
    function: DistributionFunction,
  },
}))

export const TokenConfigurationLocalization = Enum("TokenConfigurationLocalization", /** @type {const} */ ({
  V0: [TokenConfigurationLocalizationV0],
}))

/** platform_serialize unversioned */
export const TokenDistributionRecipient = Enum("TokenDistributionRecipient", /** @type {const} */ ({
  /**
   * Distribute to the contract Owner
   * default
   */
  ContractOwner: [],
  /** Distribute to a single identity */
  Identity: [Identifier],
  /**
   * Distribute tokens by participation
   *  This distribution can only happen when choosing epoch based distribution
   */
  EvonodesByParticipation: [],
}))

export const TokenKeepsHistoryRules = Enum("TokenKeepsHistoryRules", /** @type {const} */ ({
  V0: [TokenKeepsHistoryRulesV0],
}))

export const TokenPerpetualDistributionV0 = Struct("TokenPerpetualDistributionV0", {
  /** The distribution type that the token will use */
  distribution_type: RewardDistributionType,
  /** The recipient type */
  distribution_recipient: TokenDistributionRecipient,
});

export const TokenPreProgrammedDistributionV0 = Struct("TokenPreProgrammedDistributionV0", {
  distributions: Map(TimestampMillis, Map(Identifier, TokenAmount)),
});

export const AuthorizedActionTakers = Enum("AuthorizedActionTakers", /** @type {const} */ ({
  /** default */
  NoOne: [],
  ContractOwner: [],
  Identity: [Identifier],
  MainGroup: [],
  Group: [GroupContractPosition],
}))

// !ENCODE
/**
 * Instant Asset Lock Proof is a part of Identity Create and Identity Topup
 *  transitions. It is a proof that specific output of dash is locked in credits
 *  pull and the transitions can mint credits and populate identity's balance.
 *  To prove that the output is locked, a height where transaction was chain locked is provided.
 */
export const ChainAssetLockProof = Struct("ChainAssetLockProof", {
  /** Core height on which the asset lock transaction was chain locked or higher */
  core_chain_locked_height: VarUint,
  /** A reference to Asset Lock Special Transaction ID and output index in the payload */
  out_point: OutPoint,
});

export const ChangeControlRulesV0 = Struct("ChangeControlRulesV0", {
  /** This is who is authorized to make such a change */
  authorized_to_make_change: AuthorizedActionTakers,
  /** This is who is authorized to make such a change to the people authorized to make a change */
  admin_action_takers: AuthorizedActionTakers,
  /** Are we allowed to change to None in the future */
  changing_authorized_action_takers_to_no_one_allowed: Bool,
  /** Are we allowed to change the admin action takers to no one in the future */
  changing_admin_action_takers_to_no_one_allowed: Bool,
  /** Can the admin action takers change themselves */
  self_changing_admin_action_takers_allowed: Bool,
});

/**
 * platform_serialize unversioned
 * platform_serialize limit = 100000
 */
export const ContestedDocumentResourceVotePoll = Struct("ContestedDocumentResourceVotePoll", {
  contract_id: Identifier,
  document_type_name: String,
  index_name: String,
  index_values: Vec(Value),
});

/**
 * A contract bounds is the bounds that the key has influence on.
 *  For authentication keys the bounds mean that the keys can only be used to sign
 *  within the specified contract.
 *  For encryption decryption this tells clients to only use these keys for specific
 *  contracts.
 * 
 * repr u8
 */
export const ContractBounds = Enum("ContractBounds", /** @type {const} */ ({
  /** this key can only be used within a specific contract */
  SingleContract: {
    id: Identifier,
  },
  /** this key can only be used within a specific contract and for a specific document type */
  SingleContractDocumentType: {
    id: Identifier,
    document_type_name: String,
  },
}))

// !ENCODE
export const CoreScript = StructTuple("CoreScript",
  DashcoreScript,
);

export const DataContractConfig = Enum("DataContractConfig", /** @type {const} */ ({
  V0: [DataContractConfigV0],
  V1: [DataContractConfigV1],
}))

export const DataContractInSerializationFormatV0 = Struct("DataContractInSerializationFormatV0", {
  /** A unique identifier for the data contract. */
  id: Identifier,
  /** Internal configuration for the contract. */
  config: DataContractConfig,
  /** The version of this data contract. */
  version: VarUint,
  /** The identifier of the contract owner. */
  owner_id: Identifier,
  /** Shared subschemas to reuse across documents as $defs object */
  schema_defs: Option(Map(DefinitionName, Value)),
  /** Document JSON Schemas per type */
  document_schemas: Map(DocumentName, Value),
});

export const DocumentBaseTransitionV0 = Struct("DocumentBaseTransitionV0", {
  /** The document ID */
  id: Identifier,
  identity_contract_nonce: IdentityNonce,
  /** Name of document type found int the data contract associated with the `data_contract_id` */
  document_type_name: String,
  /** Data contract ID generated from the data contract's `owner_id` and `entropy` */
  data_contract_id: Identifier,
});

export const GroupStateTransitionInfo = Struct("GroupStateTransitionInfo", {
  group_contract_position: GroupContractPosition,
  action_id: Identifier,
  /** This is true if we are the proposer, otherwise we are just voting on a previous action. */
  action_is_proposer: Bool,
});

/** platform_serialize unversioned */
export const GroupV0 = Struct("GroupV0", {
  members: Map(Identifier, GroupMemberPower),
  required_power: GroupRequiredPower,
});

/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.identity_credit_transfer_state_transition"
 */
export const IdentityCreditTransferTransition = Enum("IdentityCreditTransferTransition", /** @type {const} */ ({
  V0: [IdentityCreditTransferTransitionV0],
}))

export const IdentityCreditWithdrawalTransitionV0 = Struct("IdentityCreditWithdrawalTransitionV0", {
  identity_id: Identifier,
  amount: VarUint,
  core_fee_per_byte: VarUint,
  pooling: Pooling,
  output_script: CoreScript,
  nonce: IdentityNonce,
  user_fee_increase: UserFeeIncrease,
  signature_public_key_id: NotSignable(KeyID),
  signature: NotSignable(BinaryData),
});

export const IdentityCreditWithdrawalTransitionV1 = Struct("IdentityCreditWithdrawalTransitionV1", {
  identity_id: Identifier,
  amount: VarUint,
  core_fee_per_byte: VarUint,
  pooling: Pooling,
  /** If the send to output script is None, then we send the withdrawal to the address set by core */
  output_script: Option(CoreScript),
  nonce: IdentityNonce,
  user_fee_increase: UserFeeIncrease,
  signature_public_key_id: NotSignable(KeyID),
  signature: NotSignable(BinaryData),
});

export const IdentityPublicKeyInCreationV0 = Struct("IdentityPublicKeyInCreationV0", {
  id: KeyID,
  key_type: KeyType,
  purpose: Purpose,
  security_level: SecurityLevel,
  contract_bounds: Option(ContractBounds),
  read_only: Bool,
  data: BinaryData,
  /** The signature is needed for ECDSA_SECP256K1 Key type and BLS12_381 Key type */
  signature: NotSignable(BinaryData),
});

export const IdentityPublicKeyV0 = Struct("IdentityPublicKeyV0", {
  id: KeyID,
  purpose: Purpose,
  security_level: SecurityLevel,
  contract_bounds: Option(ContractBounds),
  key_type: KeyType,
  read_only: Bool,
  data: BinaryData,
  disabled_at: Option(TimestampMillis),
});

export const TokenBaseTransitionV0 = Struct("TokenBaseTransitionV0", {
  identity_contract_nonce: IdentityNonce,
  /** ID of the token within the contract */
  token_contract_position: VarUint,
  /** Data contract ID generated from the data contract's `owner_id` and `entropy` */
  data_contract_id: Identifier,
  /** Token ID generated from the data contract ID and the token position */
  token_id: Identifier,
  /** Using group multi party rules for authentication */
  using_group_info: Option(GroupStateTransitionInfo),
});

export const TokenConfigurationConventionV0 = Struct("TokenConfigurationConventionV0", {
  /**
   * Localizations for the token name.
   *  The key must be a ISO 639 2-chars language code
   */
  localizations: Map(String, TokenConfigurationLocalization),
  decimals: VarUint,
});

/** platform_serialize unversioned */
export const TokenPerpetualDistribution = Enum("TokenPerpetualDistribution", /** @type {const} */ ({
  V0: [TokenPerpetualDistributionV0],
}))

export const TokenPreProgrammedDistribution = Enum("TokenPreProgrammedDistribution", /** @type {const} */ ({
  V0: [TokenPreProgrammedDistributionV0],
}))

/**
 * platform_serialize unversioned
 * platform_serialize limit = 100000
 */
export const VotePoll = Enum("VotePoll", /** @type {const} */ ({
  ContestedDocumentResourceVotePoll: [ContestedDocumentResourceVotePoll],
}))

export const AssetLockProof = Enum("AssetLockProof", /** @type {const} */ ({
  Instant: [InstantAssetLockProof],
  Chain: [ChainAssetLockProof],
}))

export const ChangeControlRules = Enum("ChangeControlRules", /** @type {const} */ ({
  V0: [ChangeControlRulesV0],
}))

export const DocumentBaseTransition = Enum("DocumentBaseTransition", /** @type {const} */ ({
  V0: [DocumentBaseTransitionV0],
}))

export const DocumentCreateTransitionV0 = Struct("DocumentCreateTransitionV0", {
  /** Document Base Transition */
  base: DocumentBaseTransition,
  /** Entropy used to create a Document ID. */
  entropy: FixedBytes(32),
  data: Map(String, Value),
  /**
   * Pre funded balance (for unique index conflict resolution voting - the identity will put money
   *  aside that will be used by voters to vote)
   *  This is a map of index names to the amount we want to prefund them for
   *  Since index conflict resolution is not a common feature most often nothing should be added here.
   */
  prefunded_voting_balance: Option(Tuple(String, Credits)),
});

export const DocumentDeleteTransitionV0 = Struct("DocumentDeleteTransitionV0", {
  base: DocumentBaseTransition,
});

export const DocumentPurchaseTransitionV0 = Struct("DocumentPurchaseTransitionV0", {
  base: DocumentBaseTransition,
  revision: Revision,
  price: Credits,
});

export const DocumentReplaceTransitionV0 = Struct("DocumentReplaceTransitionV0", {
  base: DocumentBaseTransition,
  revision: Revision,
  data: Map(String, Value),
});

export const DocumentTransferTransitionV0 = Struct("DocumentTransferTransitionV0", {
  base: DocumentBaseTransition,
  revision: Revision,
  recipient_owner_id: Identifier,
});

export const DocumentUpdatePriceTransitionV0 = Struct("DocumentUpdatePriceTransitionV0", {
  base: DocumentBaseTransition,
  revision: Revision,
  price: Credits,
});

/** platform_serialize unversioned */
export const Group = Enum("Group", /** @type {const} */ ({
  V0: [GroupV0],
}))

/**
 * platform_serialize unversioned
 * platform_version_path "dpp.state_transition_serialization_versions.identity_credit_withdrawal_state_transition"
 */
export const IdentityCreditWithdrawalTransition = Enum("IdentityCreditWithdrawalTransition", /** @type {const} */ ({
  V0: [IdentityCreditWithdrawalTransitionV0],
  V1: [IdentityCreditWithdrawalTransitionV1],
}))

/** platform_serialize limit = 2000 , unversioned */
export const IdentityPublicKey = Enum("IdentityPublicKey", /** @type {const} */ ({
  V0: [IdentityPublicKeyV0],
}))

export const IdentityPublicKeyInCreation = Enum("IdentityPublicKeyInCreation", /** @type {const} */ ({
  V0: [IdentityPublicKeyInCreationV0],
}))

export const IdentityTopUpTransitionV0 = Struct("IdentityTopUpTransitionV0", {
  asset_lock_proof: AssetLockProof,
  identity_id: Identifier,
  user_fee_increase: UserFeeIncrease,
  signature: NotSignable(BinaryData),
});

export const IdentityUpdateTransitionV0 = Struct("IdentityUpdateTransitionV0", {
  /** Unique identifier of the identity to be updated */
  identity_id: Identifier,
  /** The revision of the identity after update */
  revision: Revision,
  /** Identity nonce for this transition to prevent replay attacks */
  nonce: IdentityNonce,
  /**
   * Public Keys to add to the Identity
   *  we want to skip serialization of transitions, as we does it manually in `to_object()`  and `to_json()`
   */
  add_public_keys: Vec(IdentityPublicKeyInCreation),
  /** Identity Public Keys ID's to disable for the Identity */
  disable_public_keys: Vec(KeyID),
  /** The fee multiplier */
  user_fee_increase: UserFeeIncrease,
  /** The ID of the public key used to sing the State Transition */
  signature_public_key_id: NotSignable(KeyID),
  /** Cryptographic signature of the State Transition */
  signature: NotSignable(BinaryData),
});

/** platform_serialize unversioned */
export const ResourceVoteV0 = Struct("ResourceVoteV0", {
  vote_poll: VotePoll,
  resource_vote_choice: ResourceVoteChoice,
});

export const TokenBaseTransition = Enum("TokenBaseTransition", /** @type {const} */ ({
  V0: [TokenBaseTransitionV0],
}))

export const TokenBurnTransitionV0 = Struct("TokenBurnTransitionV0", {
  /** Document Base Transition */
  base: TokenBaseTransition,
  /** How much should we burn */
  burn_amount: VarUint,
  /** The public note */
  public_note: Option(String),
});

export const TokenClaimTransitionV0 = Struct("TokenClaimTransitionV0", {
  /** Document Base Transition */
  base: TokenBaseTransition,
  /** The type of distribution we are targeting */
  distribution_type: TokenDistributionType,
  /** A public note, this will only get saved to the state if we are using a historical contract */
  public_note: Option(String),
});

export const TokenConfigurationConvention = Enum("TokenConfigurationConvention", /** @type {const} */ ({
  V0: [TokenConfigurationConventionV0],
}))

export const TokenDestroyFrozenFundsTransitionV0 = Struct("TokenDestroyFrozenFundsTransitionV0", {
  /** Document Base Transition */
  base: TokenBaseTransition,
  /** The identity id of the account whose balance should be destroyed */
  frozen_identity_id: Identifier,
  /** The public note */
  public_note: Option(String),
});

export const TokenDistributionRulesV0 = Struct("TokenDistributionRulesV0", {
  perpetual_distribution: Option(TokenPerpetualDistribution),
  perpetual_distribution_rules: ChangeControlRules,
  pre_programmed_distribution: Option(TokenPreProgrammedDistribution),
  new_tokens_destination_identity: Option(Identifier),
  new_tokens_destination_identity_rules: ChangeControlRules,
  minting_allow_choosing_destination: Bool,
  minting_allow_choosing_destination_rules: ChangeControlRules,
});

export const TokenEmergencyActionTransitionV0 = Struct("TokenEmergencyActionTransitionV0", {
  /** Document Base Transition */
  base: TokenBaseTransition,
  /** The emergency action */
  emergency_action: TokenEmergencyAction,
  /** The public note */
  public_note: Option(String),
});

export const TokenFreezeTransitionV0 = Struct("TokenFreezeTransitionV0", {
  /** Document Base Transition */
  base: TokenBaseTransition,
  /** The identity that we are freezing */
  identity_to_freeze_id: Identifier,
  /** The public note */
  public_note: Option(String),
});

export const TokenMintTransitionV0 = Struct("TokenMintTransitionV0", {
  /** Document Base Transition */
  base: TokenBaseTransition,
  /**
   * Who should we issue the token to? If this is not set then we issue to the identity set in
   *  contract settings. If such an operation is allowed.
   */
  issued_to_identity_id: Option(Identifier),
  /** How much should we issue */
  amount: VarUint,
  /** The public note */
  public_note: Option(String),
});

export const TokenTransferTransitionV0 = Struct("TokenTransferTransitionV0", {
  base: TokenBaseTransition,
  amount: VarUint,
  recipient_id: Identifier,
  /** The public note */
  public_note: Option(String),
  /** An optional shared encrypted note */
  shared_encrypted_note: Option(SharedEncryptedNote),
  /** An optional private encrypted note */
  private_encrypted_note: Option(PrivateEncryptedNote),
});

export const TokenUnfreezeTransitionV0 = Struct("TokenUnfreezeTransitionV0", {
  /** Document Base Transition */
  base: TokenBaseTransition,
  /** The identity that we are freezing */
  frozen_identity_id: Identifier,
  /** The public note */
  public_note: Option(String),
});

export const DocumentCreateTransition = Enum("DocumentCreateTransition", /** @type {const} */ ({
  V0: [DocumentCreateTransitionV0],
}))

export const DocumentDeleteTransition = Enum("DocumentDeleteTransition", /** @type {const} */ ({
  V0: [DocumentDeleteTransitionV0],
}))

export const DocumentPurchaseTransition = Enum("DocumentPurchaseTransition", /** @type {const} */ ({
  V0: [DocumentPurchaseTransitionV0],
}))

export const DocumentReplaceTransition = Enum("DocumentReplaceTransition", /** @type {const} */ ({
  V0: [DocumentReplaceTransitionV0],
}))

export const DocumentTransferTransition = Enum("DocumentTransferTransition", /** @type {const} */ ({
  V0: [DocumentTransferTransitionV0],
}))

export const DocumentUpdatePriceTransition = Enum("DocumentUpdatePriceTransition", /** @type {const} */ ({
  V0: [DocumentUpdatePriceTransitionV0],
}))

export const IdentityCreateTransitionV0 = Struct("IdentityCreateTransitionV0", {
  public_keys: Vec(IdentityPublicKeyInCreation),
  asset_lock_proof: AssetLockProof,
  user_fee_increase: UserFeeIncrease,
  signature: NotSignable(BinaryData),
  identity_id: NotSignable(Identifier),
});

/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.identity_top_up_state_transition"
 */
export const IdentityTopUpTransition = Enum("IdentityTopUpTransition", /** @type {const} */ ({
  V0: [IdentityTopUpTransitionV0],
}))

/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.identity_update_state_transition"
 */
export const IdentityUpdateTransition = Enum("IdentityUpdateTransition", /** @type {const} */ ({
  V0: [IdentityUpdateTransitionV0],
}))

/** platform_serialize limit = 15000 , unversioned */
export const ResourceVote = Enum("ResourceVote", /** @type {const} */ ({
  V0: [ResourceVoteV0],
}))

export const TokenBurnTransition = Enum("TokenBurnTransition", /** @type {const} */ ({
  V0: [TokenBurnTransitionV0],
}))

export const TokenClaimTransition = Enum("TokenClaimTransition", /** @type {const} */ ({
  V0: [TokenClaimTransitionV0],
}))

export const TokenConfigurationChangeItem = Enum("TokenConfigurationChangeItem", /** @type {const} */ ({
  /** default */
  TokenConfigurationNoChange: [],
  Conventions: [TokenConfigurationConvention],
  ConventionsControlGroup: [AuthorizedActionTakers],
  ConventionsAdminGroup: [AuthorizedActionTakers],
  MaxSupply: [Option(TokenAmount)],
  MaxSupplyControlGroup: [AuthorizedActionTakers],
  MaxSupplyAdminGroup: [AuthorizedActionTakers],
  PerpetualDistribution: [Option(TokenPerpetualDistribution)],
  PerpetualDistributionControlGroup: [AuthorizedActionTakers],
  PerpetualDistributionAdminGroup: [AuthorizedActionTakers],
  NewTokensDestinationIdentity: [Option(Identifier)],
  NewTokensDestinationIdentityControlGroup: [AuthorizedActionTakers],
  NewTokensDestinationIdentityAdminGroup: [AuthorizedActionTakers],
  MintingAllowChoosingDestination: [Bool],
  MintingAllowChoosingDestinationControlGroup: [AuthorizedActionTakers],
  MintingAllowChoosingDestinationAdminGroup: [AuthorizedActionTakers],
  ManualMinting: [AuthorizedActionTakers],
  ManualMintingAdminGroup: [AuthorizedActionTakers],
  ManualBurning: [AuthorizedActionTakers],
  ManualBurningAdminGroup: [AuthorizedActionTakers],
  Freeze: [AuthorizedActionTakers],
  FreezeAdminGroup: [AuthorizedActionTakers],
  Unfreeze: [AuthorizedActionTakers],
  UnfreezeAdminGroup: [AuthorizedActionTakers],
  DestroyFrozenFunds: [AuthorizedActionTakers],
  DestroyFrozenFundsAdminGroup: [AuthorizedActionTakers],
  EmergencyAction: [AuthorizedActionTakers],
  EmergencyActionAdminGroup: [AuthorizedActionTakers],
  MainControlGroup: [Option(GroupContractPosition)],
}))

export const TokenDestroyFrozenFundsTransition = Enum("TokenDestroyFrozenFundsTransition", /** @type {const} */ ({
  V0: [TokenDestroyFrozenFundsTransitionV0],
}))

export const TokenDistributionRules = Enum("TokenDistributionRules", /** @type {const} */ ({
  V0: [TokenDistributionRulesV0],
}))

export const TokenEmergencyActionTransition = Enum("TokenEmergencyActionTransition", /** @type {const} */ ({
  V0: [TokenEmergencyActionTransitionV0],
}))

export const TokenFreezeTransition = Enum("TokenFreezeTransition", /** @type {const} */ ({
  V0: [TokenFreezeTransitionV0],
}))

export const TokenMintTransition = Enum("TokenMintTransition", /** @type {const} */ ({
  V0: [TokenMintTransitionV0],
}))

export const TokenTransferTransition = Enum("TokenTransferTransition", /** @type {const} */ ({
  V0: [TokenTransferTransitionV0],
}))

export const TokenUnfreezeTransition = Enum("TokenUnfreezeTransition", /** @type {const} */ ({
  V0: [TokenUnfreezeTransitionV0],
}))

/** platform_serialize limit = 15000 , unversioned */
export const Vote = Enum("Vote", /** @type {const} */ ({
  ResourceVote: [ResourceVote],
}))

export const DocumentTransition = Enum("DocumentTransition", /** @type {const} */ ({
  Create: [DocumentCreateTransition],
  Replace: [DocumentReplaceTransition],
  Delete: [DocumentDeleteTransition],
  Transfer: [DocumentTransferTransition],
  UpdatePrice: [DocumentUpdatePriceTransition],
  Purchase: [DocumentPurchaseTransition],
}))

/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.identity_create_state_transition"
 */
export const IdentityCreateTransition = Enum("IdentityCreateTransition", /** @type {const} */ ({
  V0: [IdentityCreateTransitionV0],
}))

/** platform_serialize unversioned */
export const MasternodeVoteTransitionV0 = Struct("MasternodeVoteTransitionV0", {
  pro_tx_hash: Identifier,
  voter_identity_id: Identifier,
  vote: Vote,
  nonce: IdentityNonce,
  signature_public_key_id: NotSignable(KeyID),
  signature: NotSignable(BinaryData),
});

export const TokenConfigUpdateTransitionV0 = Struct("TokenConfigUpdateTransitionV0", {
  /** Document Base Transition */
  base: TokenBaseTransition,
  /** Updated token configuration item */
  update_token_configuration_item: TokenConfigurationChangeItem,
  /** The public note */
  public_note: Option(String),
});

export const TokenConfigurationV0 = Struct("TokenConfigurationV0", {
  conventions: TokenConfigurationConvention,
  /** Who can change the conventions */
  conventions_change_rules: ChangeControlRules,
  /** The supply at the creation of the token */
  base_supply: TokenAmount,
  /** The maximum supply the token can ever have */
  max_supply: Option(TokenAmount),
  /** The rules for keeping history. */
  keeps_history: TokenKeepsHistoryRules,
  /** Do we start off as paused, meaning that we can not transfer till we unpause. */
  start_as_paused: Bool,
  /**
   * Who can change the max supply
   *  Even if set no one can ever change this under the base supply
   */
  max_supply_change_rules: ChangeControlRules,
  /** The distribution rules for the token */
  distribution_rules: TokenDistributionRules,
  manual_minting_rules: ChangeControlRules,
  manual_burning_rules: ChangeControlRules,
  freeze_rules: ChangeControlRules,
  unfreeze_rules: ChangeControlRules,
  destroy_frozen_funds_rules: ChangeControlRules,
  emergency_action_rules: ChangeControlRules,
  main_control_group: Option(GroupContractPosition),
  main_control_group_can_be_modified: AuthorizedActionTakers,
});

export const BatchTransitionV0 = Struct("BatchTransitionV0", {
  owner_id: Identifier,
  transitions: Vec(DocumentTransition),
  user_fee_increase: UserFeeIncrease,
  signature_public_key_id: NotSignable(KeyID),
  signature: NotSignable(BinaryData),
});

/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.masternode_vote_state_transition"
 */
export const MasternodeVoteTransition = Enum("MasternodeVoteTransition", /** @type {const} */ ({
  V0: [MasternodeVoteTransitionV0],
}))

export const TokenConfigUpdateTransition = Enum("TokenConfigUpdateTransition", /** @type {const} */ ({
  V0: [TokenConfigUpdateTransitionV0],
}))

export const TokenConfiguration = Enum("TokenConfiguration", /** @type {const} */ ({
  V0: [TokenConfigurationV0],
}))

export const TokenTransition = Enum("TokenTransition", /** @type {const} */ ({
  Burn: [TokenBurnTransition],
  Mint: [TokenMintTransition],
  Transfer: [TokenTransferTransition],
  Freeze: [TokenFreezeTransition],
  Unfreeze: [TokenUnfreezeTransition],
  DestroyFrozenFunds: [TokenDestroyFrozenFundsTransition],
  Claim: [TokenClaimTransition],
  EmergencyAction: [TokenEmergencyActionTransition],
  ConfigUpdate: [TokenConfigUpdateTransition],
}))

export const BatchedTransition = Enum("BatchedTransition", /** @type {const} */ ({
  Document: [DocumentTransition],
  Token: [TokenTransition],
}))

export const DataContractInSerializationFormatV1 = Struct("DataContractInSerializationFormatV1", {
  /** A unique identifier for the data contract. */
  id: Identifier,
  /** Internal configuration for the contract. */
  config: DataContractConfig,
  /** The version of this data contract. */
  version: VarUint,
  /** The identifier of the contract owner. */
  owner_id: Identifier,
  /** Shared subschemas to reuse across documents as $defs object */
  schema_defs: Option(Map(DefinitionName, Value)),
  /** Document JSON Schemas per type */
  document_schemas: Map(DocumentName, Value),
  /** The time in milliseconds that the contract was created. */
  created_at: Option(TimestampMillis),
  /** The time in milliseconds that the contract was last updated. */
  updated_at: Option(TimestampMillis),
  /** The block that the document was created. */
  created_at_block_height: Option(BlockHeight),
  /** The block that the contract was last updated */
  updated_at_block_height: Option(BlockHeight),
  /** The epoch at which the contract was created. */
  created_at_epoch: Option(EpochIndex),
  /** The epoch at which the contract was last updated. */
  updated_at_epoch: Option(EpochIndex),
  /** Groups that allow for specific multiparty actions on the contract */
  groups: Map(GroupContractPosition, Group),
  /** The tokens on the contract. */
  tokens: Map(TokenContractPosition, TokenConfiguration),
});

export const BatchTransitionV1 = Struct("BatchTransitionV1", {
  owner_id: Identifier,
  transitions: Vec(BatchedTransition),
  user_fee_increase: UserFeeIncrease,
  signature_public_key_id: NotSignable(KeyID),
  signature: NotSignable(BinaryData),
});

export const DataContractInSerializationFormat = Enum("DataContractInSerializationFormat", /** @type {const} */ ({
  V0: [DataContractInSerializationFormatV0],
  V1: [DataContractInSerializationFormatV1],
}))

export const DataContractUpdateTransitionV0 = Struct("DataContractUpdateTransitionV0", {
  identity_contract_nonce: IdentityNonce,
  data_contract: DataContractInSerializationFormat,
  user_fee_increase: UserFeeIncrease,
  signature_public_key_id: NotSignable(KeyID),
  signature: NotSignable(BinaryData),
});

/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.batch_state_transition"
 */
export const BatchTransition = Enum("BatchTransition", /** @type {const} */ ({
  V0: [BatchTransitionV0],
  V1: [BatchTransitionV1],
}))

/** DataContractCreateTransitionV0 has the same encoding structure */
export const DataContractCreateTransitionV0 = Struct("DataContractCreateTransitionV0", {
  data_contract: DataContractInSerializationFormat,
  identity_nonce: IdentityNonce,
  user_fee_increase: UserFeeIncrease,
  signature_public_key_id: NotSignable(KeyID),
  signature: NotSignable(BinaryData),
});

/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.contract_update_state_transition"
 */
export const DataContractUpdateTransition = Enum("DataContractUpdateTransition", /** @type {const} */ ({
  V0: [DataContractUpdateTransitionV0],
}))

/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.contract_create_state_transition"
 */
export const DataContractCreateTransition = Enum("DataContractCreateTransition", /** @type {const} */ ({
  V0: [DataContractCreateTransitionV0],
}))

/**
 * platform_serialize unversioned
 * platform_serialize limit = 100000
 */
export const StateTransition = Enum("StateTransition", /** @type {const} */ ({
  DataContractCreate: [DataContractCreateTransition],
  DataContractUpdate: [DataContractUpdateTransition],
  Batch: [BatchTransition],
  IdentityCreate: [IdentityCreateTransition],
  IdentityTopUp: [IdentityTopUpTransition],
  IdentityCreditWithdrawal: [IdentityCreditWithdrawalTransition],
  IdentityUpdate: [IdentityUpdateTransition],
  IdentityCreditTransfer: [IdentityCreditTransferTransition],
  MasternodeVote: [MasternodeVoteTransition],
}))

// NOT NEEDED: ActionGoal
// NOT NEEDED: ActionTaker
// NOT NEEDED: AddOperation
// NOT NEEDED: AddrV2
// NOT NEEDED: AddrV2Message
// NOT NEEDED: DUPLICATE_Address
// NOT NEEDED: AddressEncoding
// NOT NEEDED: AddressInner
// NOT NEEDED: AddressType
// NOT NEEDED: All
// NOT NEEDED: AllowedCurrency
// NOT NEEDED: Amount
// NOT NEEDED: Annex
// NOT NEEDED: ArrayDeserializer
// NOT NEEDED: ArrayItemType
// NOT NEEDED: AssetLockOutputNotFoundError
// NOT NEEDED: AssetLockProofType
// NOT NEEDED: AssetLockTransactionIsNotFoundError
// NOT NEEDED: AssetLockValue
// NOT NEEDED: AssetLockValueV0
// NOT NEEDED: AssetUnlockBasePayload
// NOT NEEDED: AssetUnlockBaseTransactionInfo
// NOT NEEDED: AssetUnlockPayload
// NOT NEEDED: AssetUnlockRequestInfo
// NOT NEEDED: BLSPublicKey
// NOT NEEDED: BLSSignature
// NOT NEEDED: BalanceChange
// NOT NEEDED: BalanceChangeForIdentity
// NOT NEEDED: BalanceIsNotEnoughError
// NOT NEEDED: BasicBLSError
// NOT NEEDED: BasicECDSAError
// NOT NEEDED: BasicError
// NOT NEEDED: BatchedTransitionMutRef
// NOT NEEDED: BatchedTransitionRef
// NOT NEEDED: BinVisitor
// NOT NEEDED: BinWriter
// NOT NEEDED: Bip34Error
// NOT NEEDED: BitStreamReader
// NOT NEEDED: BitStreamWriter
// NOT NEEDED: Block
// NOT NEEDED: BlockFilter
// NOT NEEDED: BlockFilterReader
// NOT NEEDED: BlockFilterWriter
// NOT NEEDED: DUPLICATE_BlockHash
// NOT NEEDED: BlockInfo
// NOT NEEDED: BlockTransactions
// NOT NEEDED: BlockTransactionsRequest
// NOT NEEDED: BlockTxn
// NOT NEEDED: BloomFlags
// NOT NEEDED: BorrowedPair
// NOT NEEDED: Builder
// NOT NEEDED: ByteArrayKeyword
// NOT NEEDED: ByteArrayPropertySizes
// NOT NEEDED: Bytes
// NOT NEEDED: Bytes20
// NOT NEEDED: Bytes32
// NOT NEEDED: Bytes36
// NOT NEEDED: BytesPerEpoch
// NOT NEEDED: BytesPerEpochByIdentifier
// NOT NEEDED: CFCheckpt
// NOT NEEDED: CFHeaders
// NOT NEEDED: CFilter
// NOT NEEDED: CachedEpochIndexFeeVersions
// NOT NEEDED: CachedEpochIndexFeeVersionsFieldsBeforeVersion4
// NOT NEEDED: CborCanonicalMap
// NOT NEEDED: ChainCode
// NOT NEEDED: ChainHash
// NOT NEEDED: ChainLock
// NOT NEEDED: CheckedData
// NOT NEEDED: ChildNumber
// NOT NEEDED: ChoosingTokenMintRecipientNotAllowedError
// NOT NEEDED: Class
// NOT NEEDED: ClassifyContext
// NOT NEEDED: ClientDataRetrievalError
// NOT NEEDED: CmpctBlock
// NOT NEEDED: CoinbasePayload
// NOT NEEDED: CommandString
// NOT NEEDED: CommandStringError
// NOT NEEDED: CommonCache
// NOT NEEDED: CompactTarget
// NOT NEEDED: CompatibleProtocolVersionIsNotDefinedError
// NOT NEEDED: ConfirmedHash
// NOT NEEDED: ConfirmedHashHashedWithProRegTx
// NOT NEEDED: ConsensusError
// NOT NEEDED: ConsensusValidationResult
// NOT NEEDED: Contender
// NOT NEEDED: ContenderV0
// NOT NEEDED: ContenderWithSerializedDocument
// NOT NEEDED: ContenderWithSerializedDocumentV0
// NOT NEEDED: ContestedDocumentVotePollStatus
// NOT NEEDED: ContestedDocumentVotePollStoredInfo
// NOT NEEDED: ContestedDocumentVotePollStoredInfoV0
// NOT NEEDED: ContestedDocumentVotePollStoredInfoVoteEventV0
// NOT NEEDED: ContestedDocumentVotePollWinnerInfo
// NOT NEEDED: ContestedDocumentsTemporarilyNotAllowedError
// NOT NEEDED: ContestedIndexFieldMatch
// NOT NEEDED: ContestedIndexInformation
// NOT NEEDED: ContestedIndexResolution
// NOT NEEDED: ContestedUniqueIndexOnMutableDocumentTypeError
// NOT NEEDED: ContestedUniqueIndexWithUniqueIndexError
// NOT NEEDED: ContractBoundsType
// NOT NEEDED: ContractHasNoTokensError
// NOT NEEDED: ControlBlock
// NOT NEEDED: ConversionError
// NOT NEEDED: CopyOperation
// NOT NEEDED: DUPLICATE_CoreBlockHeight
// NOT NEEDED: CreatedDataContract
// NOT NEEDED: CreatedDataContractInSerializationFormat
// NOT NEEDED: CreatedDataContractInSerializationFormatV0
// NOT NEEDED: CreatedDataContractV0
// NOT NEEDED: CreationRestrictionMode
// NOT NEEDED: CreditsPerEpoch
// NOT NEEDED: CreditsPerEpochByIdentifier
// NOT NEEDED: CycleHash
// NOT NEEDED: DKGParams
// NOT NEEDED: DPPError
// NOT NEEDED: DUPLICATE_DashPlatformProtocol
// NOT NEEDED: DashPlatformProtocolInitError
// NOT NEEDED: DataBuilder
// NOT NEEDED: DataContract
// NOT NEEDED: DataContractAlreadyPresentError
// NOT NEEDED: DataContractBoundsNotPresentError
// NOT NEEDED: DataContractConfigUpdateError
// NOT NEEDED: DataContractCreateTransitionLatest
// NOT NEEDED: DataContractError
// NOT NEEDED: DataContractFacade
// NOT NEEDED: DataContractFactory
// NOT NEEDED: DataContractFactoryV0
// NOT NEEDED: DataContractHaveNewUniqueIndexError
// NOT NEEDED: DataContractImmutablePropertiesUpdateError
// NOT NEEDED: DataContractInvalidIndexDefinitionUpdateError
// NOT NEEDED: DataContractIsReadonlyError
// NOT NEEDED: DataContractMaxDepthExceedError
// NOT NEEDED: DUPLICATE_DataContractNotPresentError
// NOT NEEDED: DataContractTokenConfigurationUpdateError
// NOT NEEDED: DataContractUniqueIndicesChangedError
// NOT NEEDED: DataContractUpdateActionNotAllowedError
// NOT NEEDED: DataContractUpdatePermissionError
// NOT NEEDED: DataContractUpdateTransitionLatest
// NOT NEEDED: DataContractV0
// NOT NEEDED: DataContractV1
// NOT NEEDED: DataTriggerConditionError
// NOT NEEDED: DataTriggerError
// NOT NEEDED: DataTriggerExecutionError
// NOT NEEDED: DataTriggerInvalidResultError
// NOT NEEDED: DUPLICATE_DecodeError
// NOT NEEDED: DecodeInitError
// NOT NEEDED: DecodeProtocolIdentity
// NOT NEEDED: Decoder
// NOT NEEDED: DecodingError
// NOT NEEDED: DefaultEntropyGenerator
// NOT NEEDED: DeletedQuorum
// NOT NEEDED: Denomination
// NOT NEEDED: DerivationPath
// NOT NEEDED: DerivationPathIterator
// NOT NEEDED: DerivationPathReference
// NOT NEEDED: Deserializer
// NOT NEEDED: DestinationIdentityForTokenMintingNotSetError
// NOT NEEDED: DisablingKeyIdAlsoBeingAddedInSameTransitionError
// NOT NEEDED: Display
// NOT NEEDED: DisplayExpected
// NOT NEEDED: DisplayStyle
// NOT NEEDED: DisplayUnchecked
// NOT NEEDED: DisplayWrapper
// NOT NEEDED: DistributionAmount
// NOT NEEDED: DistributionLeftovers
// NOT NEEDED: Document
// NOT NEEDED: DocumentAlreadyPresentError
// NOT NEEDED: DocumentBatchIterator
// NOT NEEDED: DocumentBatchV1Iterator
// NOT NEEDED: DocumentContestCurrentlyLockedError
// NOT NEEDED: DocumentContestDocumentWithSameIdAlreadyPresentError
// NOT NEEDED: DocumentContestIdentityAlreadyContestantError
// NOT NEEDED: DocumentContestNotJoinableError
// NOT NEEDED: DocumentContestNotPaidForError
// NOT NEEDED: DocumentCreationNotAllowedError
// NOT NEEDED: DocumentError
// NOT NEEDED: DocumentFacade
// NOT NEEDED: DocumentFactory
// NOT NEEDED: DocumentFactoryV0
// NOT NEEDED: DocumentFieldFillSize
// NOT NEEDED: DocumentFieldFillType
// NOT NEEDED: DocumentFieldMaxSizeExceededError
// NOT NEEDED: DocumentForCbor
// NOT NEEDED: DocumentIncorrectPurchasePriceError
// NOT NEEDED: DocumentNotForSaleError
// NOT NEEDED: DocumentNotFoundError
// NOT NEEDED: DocumentOwnerIdMismatchError
// NOT NEEDED: DocumentPatch
// NOT NEEDED: DocumentProperty
// NOT NEEDED: DocumentPropertyType
// NOT NEEDED: DocumentPropertyTypeParsingOptions
// NOT NEEDED: DocumentTimestampWindowViolationError
// NOT NEEDED: DocumentTimestampsAreEqualError
// NOT NEEDED: DocumentTimestampsMismatchError
// NOT NEEDED: DocumentTransitionActionType
// NOT NEEDED: DocumentTransitionsAreAbsentError
// NOT NEEDED: DocumentType
// NOT NEEDED: DocumentTypeMutRef
// NOT NEEDED: DocumentTypeRef
// NOT NEEDED: DocumentTypeUpdateError
// NOT NEEDED: DocumentTypeV0
// NOT NEEDED: DocumentTypeV1
// NOT NEEDED: DocumentTypesAreMissingError
// NOT NEEDED: DocumentV0
// NOT NEEDED: Duffs
// NOT NEEDED: DuplicateDocumentTransitionsWithIdsError
// NOT NEEDED: DuplicateDocumentTransitionsWithIndicesError
// NOT NEEDED: DuplicateIndexError
// NOT NEEDED: DuplicateIndexNameError
// NOT NEEDED: DuplicateUniqueIndexError
// NOT NEEDED: DuplicatedIdentityPublicKeyBasicError
// NOT NEEDED: DuplicatedIdentityPublicKeyIdBasicError
// NOT NEEDED: DuplicatedIdentityPublicKeyIdStateError
// NOT NEEDED: DuplicatedIdentityPublicKeyStateError
// NOT NEEDED: DUPLICATE_EcdsaSighashType
// NOT NEEDED: EmptyWrite
// NOT NEEDED: EncodeSigningDataResult
// NOT NEEDED: Encoder
// NOT NEEDED: Encoding
// NOT NEEDED: EntryMasternodeType
// NOT NEEDED: Epoch
// NOT NEEDED: EpochIndexFeeVersionsForStorage
// NOT NEEDED: DUPLICATE_Error
// NOT NEEDED: ErrorTrackingWriter
// NOT NEEDED: ExpectedDocumentsData
// NOT NEEDED: ExtendedBlockInfo
// NOT NEEDED: ExtendedBlockInfoV0
// NOT NEEDED: ExtendedDocument
// NOT NEEDED: ExtendedDocumentV0
// NOT NEEDED: ExtendedDocumentVisitor
// NOT NEEDED: ExtendedEpochInfo
// NOT NEEDED: ExtendedEpochInfoV0
// NOT NEEDED: ExtendedPrivKey
// NOT NEEDED: ExtendedPubKey
// NOT NEEDED: FeeError
// NOT NEEDED: FeeMultiplier
// NOT NEEDED: FeeRate
// NOT NEEDED: FeeRefunds
// NOT NEEDED: FeeResult
// NOT NEEDED: FetchAndValidateDataContract
// NOT NEEDED: FieldMinMaxBounds
// NOT NEEDED: FieldType
// NOT NEEDED: FieldTypeWeights
// NOT NEEDED: FilterAdd
// NOT NEEDED: FilterHash
// NOT NEEDED: FilterHeader
// NOT NEEDED: FilterLoad
// NOT NEEDED: FinalizedContender
// NOT NEEDED: FinalizedContenderWithSerializedDocument
// NOT NEEDED: FinalizedEpochInfo
// NOT NEEDED: FinalizedEpochInfoV0
// NOT NEEDED: FinalizedResourceVoteChoicesWithVoterInfo
// NOT NEEDED: Fingerprint
// NOT NEEDED: FormatOptions
// NOT NEEDED: FromHexError
// NOT NEEDED: FrozenIdentifier
// NOT NEEDED: FutureLeafVersion
// NOT NEEDED: GcsFilter
// NOT NEEDED: GcsFilterReader
// NOT NEEDED: GcsFilterWriter
// NOT NEEDED: GetBlockTxn
// NOT NEEDED: GetBlocksMessage
// NOT NEEDED: GetCFCheckpt
// NOT NEEDED: GetCFHeaders
// NOT NEEDED: GetCFilters
// NOT NEEDED: GetDataContractSecurityLevelRequirementFn
// NOT NEEDED: GetHeadersMessage
// NOT NEEDED: GetKeyError
// NOT NEEDED: GetMnListDiff
// NOT NEEDED: GetQRInfo
// NOT NEEDED: GroupAction
// NOT NEEDED: GroupActionAlreadyCompletedError
// NOT NEEDED: GroupActionAlreadySignedByIdentityError
// NOT NEEDED: GroupActionDoesNotExistError
// NOT NEEDED: GroupActionEvent
// NOT NEEDED: GroupActionNotAllowedOnTransitionError
// NOT NEEDED: GroupActionStatus
// NOT NEEDED: GroupActionV0
// NOT NEEDED: GroupExceedsMaxMembersError
// NOT NEEDED: GroupMemberHasPowerOfZeroError
// NOT NEEDED: GroupMemberHasPowerOverLimitError
// NOT NEEDED: GroupNonUnilateralMemberPowerHasLessThanRequiredPowerError
// NOT NEEDED: GroupPositionDoesNotExistError
// NOT NEEDED: GroupStateTransitionInfoStatus
// NOT NEEDED: GroupStateTransitionResolvedInfo
// NOT NEEDED: GroupSumPower
// NOT NEEDED: GroupTotalPowerLessThanRequiredError
// NOT NEEDED: HRVisitor
// NOT NEEDED: Header
// NOT NEEDED: HeaderAndShortIds
// NOT NEEDED: HeaderDeserializationWrapper
// NOT NEEDED: HeaderSerializationWrapper
// NOT NEEDED: DUPLICATE_Height
// NOT NEEDED: Hex
// NOT NEEDED: HiddenNodes
// NOT NEEDED: IHeader
// NOT NEEDED: IdentitiesContractKeys
// NOT NEEDED: Identity
// NOT NEEDED: IdentityAlreadyExistsError
// NOT NEEDED: IdentityAssetLockProofLockedTransactionMismatchError
// NOT NEEDED: IdentityAssetLockStateTransitionReplayError
// NOT NEEDED: IdentityAssetLockTransactionIsNotFoundError
// NOT NEEDED: IdentityAssetLockTransactionOutPointAlreadyConsumedError
// NOT NEEDED: IdentityAssetLockTransactionOutPointNotEnoughBalanceError
// NOT NEEDED: IdentityAssetLockTransactionOutputNotFoundError
// NOT NEEDED: IdentityCreateTransitionLatest
// NOT NEEDED: IdentityCreateTransitionV0Inner
// NOT NEEDED: IdentityCreditTransferToSelfError
// NOT NEEDED: IdentityCreditTransferTransitionLatest
// NOT NEEDED: IdentityCreditWithdrawalTransitionLatest
// NOT NEEDED: IdentityCreditWithdrawalTransitionV01
// NOT NEEDED: IdentityCreditWithdrawalTransitionV010
// NOT NEEDED: IdentityCreditWithdrawalTransitionV02
// NOT NEEDED: IdentityCreditWithdrawalTransitionV03
// NOT NEEDED: IdentityCreditWithdrawalTransitionV04
// NOT NEEDED: IdentityCreditWithdrawalTransitionV05
// NOT NEEDED: IdentityCreditWithdrawalTransitionV06
// NOT NEEDED: IdentityCreditWithdrawalTransitionV07
// NOT NEEDED: IdentityCreditWithdrawalTransitionV08
// NOT NEEDED: IdentityCreditWithdrawalTransitionV09
// NOT NEEDED: IdentityDoesNotHaveEnoughTokenBalanceError
// NOT NEEDED: IdentityFacade
// NOT NEEDED: IdentityFactory
// NOT NEEDED: IdentityInsufficientBalanceError
// NOT NEEDED: IdentityNotFoundError
// NOT NEEDED: IdentityNotMemberOfGroupError
// NOT NEEDED: IdentityNotPresentError
// NOT NEEDED: IdentityPublicKeyAlreadyExistsForUniqueContractBoundsError
// NOT NEEDED: IdentityPublicKeyIsDisabledError
// NOT NEEDED: IdentityPublicKeyIsReadOnlyError
// NOT NEEDED: IdentityTokenAccountAlreadyFrozenError
// NOT NEEDED: IdentityTokenAccountFrozenError
// NOT NEEDED: IdentityTokenAccountNotFrozenError
// NOT NEEDED: IdentityTokenInfo
// NOT NEEDED: IdentityTokenInfoV0
// NOT NEEDED: IdentityV0
// NOT NEEDED: IncompatibleDataContractSchemaError
// NOT NEEDED: IncompatibleDocumentTypeSchemaError
// NOT NEEDED: IncompatibleJsonSchemaOperation
// NOT NEEDED: IncompatibleProtocolVersionError
// NOT NEEDED: IncompatibleRe2PatternError
// NOT NEEDED: IncompleteBuilder
// NOT NEEDED: InconsistentCompoundIndexDataError
// NOT NEEDED: Index
// NOT NEEDED: IndexConstPath
// NOT NEEDED: IndexLevel
// NOT NEEDED: IndexLevelTypeInfo
// NOT NEEDED: IndexName
// NOT NEEDED: IndexOrderDirection
// NOT NEEDED: IndexProperties
// NOT NEEDED: IndexProperty
// NOT NEEDED: IndexPropertyName
// NOT NEEDED: IndexType
// NOT NEEDED: Input
// NOT NEEDED: InputWeightPrediction
// NOT NEEDED: InputsHash
// NOT NEEDED: DUPLICATE_InstantLock
// NOT NEEDED: Instruction
// NOT NEEDED: InstructionIndices
// NOT NEEDED: Instructions
// NOT NEEDED: IntegerReplacementType
// NOT NEEDED: InvalidActionIdError
// NOT NEEDED: InvalidAssetLockProofCoreChainHeightError
// NOT NEEDED: InvalidAssetLockProofTransactionHeightError
// NOT NEEDED: InvalidAssetLockTransactionOutputReturnSizeError
// NOT NEEDED: InvalidCompoundIndexError
// NOT NEEDED: InvalidDataContractIdError
// NOT NEEDED: InvalidDataContractVersionError
// NOT NEEDED: InvalidDocumentRevisionError
// NOT NEEDED: InvalidDocumentTransitionActionError
// NOT NEEDED: InvalidDocumentTransitionIdError
// NOT NEEDED: DUPLICATE_InvalidDocumentTypeError
// NOT NEEDED: InvalidDocumentTypeNameError
// NOT NEEDED: InvalidDocumentTypeRequiredSecurityLevelError
// NOT NEEDED: InvalidGroupPositionError
// NOT NEEDED: InvalidIdentifierError
// NOT NEEDED: InvalidIdentityAssetLockProofChainLockValidationError
// NOT NEEDED: InvalidIdentityAssetLockTransactionError
// NOT NEEDED: InvalidIdentityAssetLockTransactionOutputError
// NOT NEEDED: InvalidIdentityCreditTransferAmountError
// NOT NEEDED: InvalidIdentityCreditWithdrawalTransitionAmountError
// NOT NEEDED: InvalidIdentityCreditWithdrawalTransitionCoreFeeError
// NOT NEEDED: InvalidIdentityCreditWithdrawalTransitionOutputScriptError
// NOT NEEDED: InvalidIdentityKeySignatureError
// NOT NEEDED: InvalidIdentityNonceError
// NOT NEEDED: InvalidIdentityPublicKeyDataError
// NOT NEEDED: InvalidIdentityPublicKeyIdError
// NOT NEEDED: InvalidIdentityPublicKeySecurityLevelError
// NOT NEEDED: DUPLICATE_InvalidIdentityPublicKeyTypeError
// NOT NEEDED: InvalidIdentityRevisionError
// NOT NEEDED: InvalidIdentityUpdateTransitionDisableKeysError
// NOT NEEDED: InvalidIdentityUpdateTransitionEmptyError
// NOT NEEDED: InvalidIndexPropertyTypeError
// NOT NEEDED: InvalidIndexedPropertyConstraintError
// NOT NEEDED: InvalidInstantAssetLockProofError
// NOT NEEDED: InvalidInstantAssetLockProofSignatureError
// NOT NEEDED: InvalidJsonSchemaRefError
// NOT NEEDED: InvalidSignaturePublicKeyError
// NOT NEEDED: InvalidSignaturePublicKeyPurposeError
// NOT NEEDED: InvalidSignaturePublicKeySecurityLevelError
// NOT NEEDED: InvalidStateTransitionSignatureError
// NOT NEEDED: InvalidStateTransitionTypeError
// NOT NEEDED: InvalidTokenAmountError
// NOT NEEDED: InvalidTokenBaseSupplyError
// NOT NEEDED: InvalidTokenClaimNoCurrentRewards
// NOT NEEDED: InvalidTokenClaimPropertyMismatch
// NOT NEEDED: InvalidTokenClaimWrongClaimant
// NOT NEEDED: InvalidTokenConfigUpdateNoChangeError
// NOT NEEDED: InvalidTokenDistributionFunctionDivideByZeroError
// NOT NEEDED: InvalidTokenDistributionFunctionIncoherenceError
// NOT NEEDED: InvalidTokenDistributionFunctionInvalidParameterError
// NOT NEEDED: InvalidTokenDistributionFunctionInvalidParameterTupleError
// NOT NEEDED: InvalidTokenIdError
// NOT NEEDED: InvalidTokenNoteTooBigError
// NOT NEEDED: InvalidTokenPositionError
// NOT NEEDED: InvalidVectorSizeError
// NOT NEEDED: Inventory
// NOT NEEDED: IoWrapper
// NOT NEEDED: IsIndexUnique
// NOT NEEDED: Iter
// NOT NEEDED: IterReader
// NOT NEEDED: JsonPath
// NOT NEEDED: JsonPathLiteral
// NOT NEEDED: JsonPathStep
// NOT NEEDED: JsonSchema
// NOT NEEDED: JsonSchemaCompilationError
// NOT NEEDED: DUPLICATE_JsonSchemaError
// NOT NEEDED: JsonSchemaErrorData
// NOT NEEDED: DUPLICATE_JsonSchemaValidator
// NOT NEEDED: JsonStateTransitionSerializationOptions
// NOT NEEDED: Key
// NOT NEEDED: KeyCount
// NOT NEEDED: KeyDerivationType
// NOT NEEDED: KeyRequest
// NOT NEEDED: KeySource
// NOT NEEDED: Keys
// NOT NEEDED: KnownCostItem
// NOT NEEDED: LLMQEntryVerificationSkipStatus
// NOT NEEDED: LLMQEntryVerificationStatus
// NOT NEEDED: LLMQModifierType
// NOT NEEDED: LLMQParams
// NOT NEEDED: LLMQQuarterReconstructionType
// NOT NEEDED: LLMQQuarterType
// NOT NEEDED: LLMQQuarterUsageType
// NOT NEEDED: LLMQType
// NOT NEEDED: LazyRegex
// NOT NEEDED: LeafNode
// NOT NEEDED: LeafNodes
// NOT NEEDED: LeafVersion
// NOT NEEDED: LegacySighash
// NOT NEEDED: DUPLICATE_LockTime
// NOT NEEDED: LockTimeUnit
// NOT NEEDED: LockedVotePollCounter
// NOT NEEDED: Lower
// NOT NEEDED: MNSkipListMode
// NOT NEEDED: MapKeySerializer
// NOT NEEDED: MasterPublicKeyUpdateError
// NOT NEEDED: MasternodeIncorrectVoterIdentityIdError
// NOT NEEDED: MasternodeIncorrectVotingAddressError
// NOT NEEDED: MasternodeList
// NOT NEEDED: MasternodeListBuilder
// NOT NEEDED: MasternodeListEngine
// NOT NEEDED: MasternodeListEntry
// NOT NEEDED: MasternodeNotFoundError
// NOT NEEDED: MasternodeVoteAlreadyPresentError
// NOT NEEDED: MasternodeVoteTransitionLatest
// NOT NEEDED: MasternodeVotedTooManyTimesError
// NOT NEEDED: MaxDepthValidationResult
// NOT NEEDED: MaxDocumentsTransitionsExceededError
// NOT NEEDED: MaxIdentityPublicKeyLimitReachedError
// NOT NEEDED: MergeIdentityNonceResult
// NOT NEEDED: MerkleBlock
// NOT NEEDED: MerkleBlockError
// NOT NEEDED: MerkleRootMasternodeList
// NOT NEEDED: MerkleRootQuorums
// NOT NEEDED: MessageSignature
// NOT NEEDED: MessageSignatureError
// NOT NEEDED: MessageVerificationError
// NOT NEEDED: Metadata
// NOT NEEDED: MissingDataContractIdBasicError
// NOT NEEDED: MissingDefaultLocalizationError
// NOT NEEDED: MissingDocumentTransitionActionError
// NOT NEEDED: MissingDocumentTransitionTypeError
// NOT NEEDED: MissingDocumentTypeError
// NOT NEEDED: MissingIdentityPublicKeyIdsError
// NOT NEEDED: MissingMasterPublicKeyError
// NOT NEEDED: MissingPositionsInDocumentTypePropertiesError
// NOT NEEDED: MissingPublicKeyError
// NOT NEEDED: MissingStateTransitionTypeError
// NOT NEEDED: MissingTransferKeyError
// NOT NEEDED: MnListDiff
// NOT NEEDED: MoveOperation
// NOT NEEDED: NativeBlsModule
// NOT NEEDED: Network
// NOT NEEDED: NetworkChecked
// NOT NEEDED: NetworkMessage
// NOT NEEDED: NetworkUnchecked
// NOT NEEDED: NewAuthorizedActionTakerGroupDoesNotExistError
// NOT NEEDED: NewAuthorizedActionTakerIdentityDoesNotExistError
// NOT NEEDED: NewAuthorizedActionTakerMainGroupNotSetError
// NOT NEEDED: NewTokensDestinationIdentityDoesNotExistError
// NOT NEEDED: NoTransferKeyForCoreWithdrawalAvailableError
// NOT NEEDED: NodeInfo
// NOT NEEDED: NonConsensusError
// NOT NEEDED: NonContiguousContractGroupPositionsError
// NOT NEEDED: NonContiguousContractTokenPositionsError
// NOT NEEDED: DUPLICATE_NonStandardSighashType
// NOT NEEDED: NonceOutOfBoundsError
// NOT NEEDED: NotImplementedIdentityCreditWithdrawalTransitionPoolingError
// NOT NEEDED: OperationError
// NOT NEEDED: OperatorPublicKey
// NOT NEEDED: OrderBy
// NOT NEEDED: Output
// NOT NEEDED: OutputType
// NOT NEEDED: OverflowError
// NOT NEEDED: OwnedPair
// NOT NEEDED: Pair
// NOT NEEDED: Params
// NOT NEEDED: ParentDocumentOptions
// NOT NEEDED: ParseAmountError
// NOT NEEDED: ParseIntError
// NOT NEEDED: ParseNetworkError
// NOT NEEDED: ParseOutPointError
// NOT NEEDED: PartialIdentity
// NOT NEEDED: PartialMerkleTree
// NOT NEEDED: PartiallySignedTransaction
// NOT NEEDED: PastAssetLockStateTransitionHashes
// NOT NEEDED: Patch
// NOT NEEDED: PatchDiffer
// NOT NEEDED: PatchError
// NOT NEEDED: PatchErrorKind
// NOT NEEDED: PatchOperation
// NOT NEEDED: Payload
// NOT NEEDED: PlatformItemKey
// NOT NEEDED: PreferredKeyPurposeForSigningWithdrawal
// NOT NEEDED: PrefilledTransaction
// NOT NEEDED: PrefundedSpecializedBalanceIdentifier
// NOT NEEDED: PrefundedSpecializedBalanceInsufficientError
// NOT NEEDED: PrefundedSpecializedBalanceNotFoundError
// NOT NEEDED: Prevouts
// NOT NEEDED: PrivateKey
// NOT NEEDED: ProTxHash
// NOT NEEDED: PropertyPath
// NOT NEEDED: ProprietaryKey
// NOT NEEDED: ProprietaryType
// NOT NEEDED: ProtocolError
// NOT NEEDED: ProtocolValidationOperation
// NOT NEEDED: ProtocolVersion
// NOT NEEDED: ProtocolVersionParsingError
// NOT NEEDED: ProtocolVersionVoteCount
// NOT NEEDED: ProviderMasternodeType
// NOT NEEDED: ProviderRegistrationPayload
// NOT NEEDED: ProviderUpdateRegistrarPayload
// NOT NEEDED: ProviderUpdateRevocationPayload
// NOT NEEDED: ProviderUpdateServicePayload
// NOT NEEDED: Psbt
// NOT NEEDED: PsbtHash
// NOT NEEDED: PsbtParseError
// NOT NEEDED: PsbtSighashType
// NOT NEEDED: PubkeyHash
// NOT NEEDED: PublicKey
// NOT NEEDED: PublicKeyIsDisabledError
// NOT NEEDED: PublicKeyMismatchError
// NOT NEEDED: DUPLICATE_PublicKeySecurityLevelNotMetError
// NOT NEEDED: PublicKeyValidationError
// NOT NEEDED: PushBytes
// NOT NEEDED: PushBytesBuf
// NOT NEEDED: DUPLICATE_PushBytesError
// NOT NEEDED: PushDataLenLen
// NOT NEEDED: QRInfo
// NOT NEEDED: QualifiedMasternodeListEntry
// NOT NEEDED: QualifiedQuorumEntry
// NOT NEEDED: QuorumCLSigObject
// NOT NEEDED: QuorumCommitmentHash
// NOT NEEDED: QuorumCommitmentPayload
// NOT NEEDED: QuorumEntry
// NOT NEEDED: QuorumEntryHash
// NOT NEEDED: QuorumHash
// NOT NEEDED: QuorumModifierHash
// NOT NEEDED: QuorumOrderingHash
// NOT NEEDED: QuorumSigningRequestId
// NOT NEEDED: QuorumSigningSignId
// NOT NEEDED: QuorumSnapshot
// NOT NEEDED: QuorumVVecHash
// NOT NEEDED: QuorumValidationError
// NOT NEEDED: RandomDocumentTypeParameters
// NOT NEEDED: RawAssetLockProof
// NOT NEEDED: RawNetworkMessage
// NOT NEEDED: ReadBytesFromFiniteReaderOpts
// NOT NEEDED: RecipientIdentifier
// NOT NEEDED: RecipientIdentityDoesNotExistError
// NOT NEEDED: Reject
// NOT NEEDED: RejectReason
// NOT NEEDED: RemoveOperation
// NOT NEEDED: ReplaceOperation
// NOT NEEDED: ReplacementType
// NOT NEEDED: RequiredSigners
// NOT NEEDED: RewardDistributionMoment
// NOT NEEDED: RewardRatio
// NOT NEEDED: SMLEntry
// NOT NEEDED: SMLStore
// NOT NEEDED: Script
// NOT NEEDED: ScriptHash
// NOT NEEDED: ScriptLeaf
// NOT NEEDED: ScriptLeaves
// NOT NEEDED: ScriptMerkleProofMap
// NOT NEEDED: ScriptPath
// NOT NEEDED: SegwitCache
// NOT NEEDED: SegwitV0Sighash
// NOT NEEDED: SendCmpct
// NOT NEEDED: SeqIterator
// NOT NEEDED: SerdeParsingError
// NOT NEEDED: SerializeBytesAsHex
// NOT NEEDED: SerializeMap
// NOT NEEDED: SerializeStructVariant
// NOT NEEDED: SerializeTupleVariant
// NOT NEEDED: SerializeVec
// NOT NEEDED: SerializedObjectParsingError
// NOT NEEDED: SerializedSignature
// NOT NEEDED: Serializer
// NOT NEEDED: ServiceFlags
// NOT NEEDED: Sha256dHash
// NOT NEEDED: ShortId
// NOT NEEDED: ShouldInsertWithAllNull
// NOT NEEDED: SigHashCache
// NOT NEEDED: SigHashType
// NOT NEEDED: SighashCache
// NOT NEEDED: SighashComponents
// NOT NEEDED: DUPLICATE_SighashTypeParseError
// NOT NEEDED: SignError
// NOT NEEDED: SignableBytesHasher
// NOT NEEDED: DUPLICATE_Signature
// NOT NEEDED: SignatureError
// NOT NEEDED: SignatureShouldNotBePresentError
// NOT NEEDED: SignedAmount
// NOT NEEDED: SignedCredits
// NOT NEEDED: SignedCreditsPerEpoch
// NOT NEEDED: SignedTokenAmount
// NOT NEEDED: SigningAlgorithm
// NOT NEEDED: SigningErrors
// NOT NEEDED: SigningKeys
// NOT NEEDED: SimpleConsensusValidationResult
// NOT NEEDED: SimpleValidationResult
// NOT NEEDED: SimplifiedMNList
// NOT NEEDED: Sink
// NOT NEEDED: SmallVec
// NOT NEEDED: SmlError
// NOT NEEDED: SortKey
// NOT NEEDED: SpecialTransactionPayloadHash
// NOT NEEDED: SpecializedDocumentFactory
// NOT NEEDED: SpecializedDocumentFactoryV0
// NOT NEEDED: SplitFeatureVersionOutcome
// NOT NEEDED: StartAtIncluded
// NOT NEEDED: StateError
// NOT NEEDED: StateTransitionError
// NOT NEEDED: StateTransitionFactory
// NOT NEEDED: StateTransitionIsNotSignedError
// NOT NEEDED: StateTransitionMaxSizeExceededError
// NOT NEEDED: StateTransitionProofResult
// NOT NEEDED: StateTransitionType
// NOT NEEDED: StatelessJsonSchemaLazyValidator
// NOT NEEDED: StorageAndProcessingPoolCredits
// NOT NEEDED: StoredAssetLockInfo
// NOT NEEDED: StringPropertySizes
// NOT NEEDED: SubValidator
// NOT NEEDED: SumTokenAmount
// NOT NEEDED: SystemPropertyIndexAlreadyPresentError
// NOT NEEDED: TapLeaf
// NOT NEEDED: TapSighashType
// NOT NEEDED: TapTree
// NOT NEEDED: TaprootBuilder
// NOT NEEDED: TaprootBuilderError
// NOT NEEDED: TaprootCache
// NOT NEEDED: TaprootError
// NOT NEEDED: TaprootMerkleBranch
// NOT NEEDED: TaprootSpendInfo
// NOT NEEDED: Target
// NOT NEEDED: TestConsensusError
// NOT NEEDED: DUPLICATE_TestData
// NOT NEEDED: TestOperation
// NOT NEEDED: DUPLICATE_Time
// NOT NEEDED: TimestampIncluded
// NOT NEEDED: TokenAlreadyPausedError
// NOT NEEDED: TokenCosts
// NOT NEEDED: TokenCostsV0
// NOT NEEDED: TokenDistributionInfo
// NOT NEEDED: TokenDistributionKey
// NOT NEEDED: TokenDistributionResolvedRecipient
// NOT NEEDED: TokenDistributionTypeWithResolvedRecipient
// NOT NEEDED: TokenDistributionWeight
// NOT NEEDED: TokenError
// NOT NEEDED: TokenEvent
// NOT NEEDED: TokenEventPersonalEncryptedNote
// NOT NEEDED: TokenEventPublicNote
// NOT NEEDED: TokenEventSharedEncryptedNote
// NOT NEEDED: TokenIsPausedError
// NOT NEEDED: TokenMintPastMaxSupplyError
// NOT NEEDED: TokenName
// NOT NEEDED: TokenNotPausedError
// NOT NEEDED: TokenSettingMaxSupplyToLessThanCurrentSupplyError
// NOT NEEDED: TokenStatus
// NOT NEEDED: TokenStatusV0
// NOT NEEDED: TokenTransferRecipientIdentityNotExistError
// NOT NEEDED: TokenTransferToOurselfError
// NOT NEEDED: TokenTransitionActionType
// NOT NEEDED: TooManyMasterPublicKeyError
// NOT NEEDED: TotalCreditsBalance
// NOT NEEDED: TotalSingleTokenBalance
// NOT NEEDED: TotalTokensBalance
// NOT NEEDED: TradeMode
// NOT NEEDED: TransactionPayload
// NOT NEEDED: TransactionType
// NOT NEEDED: Transferable
// NOT NEEDED: TransitionFingerprint
// NOT NEEDED: TryFromError
// NOT NEEDED: TweakedKeyPair
// NOT NEEDED: TweakedPublicKey
// NOT NEEDED: TxIn
// NOT NEEDED: TxIndexOutOfRangeError
// NOT NEEDED: TxMerkleNode
// NOT NEEDED: Type
// NOT NEEDED: U256
// NOT NEEDED: UintError
// NOT NEEDED: UnauthorizedTokenActionError
// NOT NEEDED: UndefinedIndexPropertyError
// NOT NEEDED: UniqueIndicesLimitReachedError
// NOT NEEDED: UnknownAssetLockProofTypeError
// NOT NEEDED: UnknownChainHash
// NOT NEEDED: UnknownDocumentCreationRestrictionModeError
// NOT NEEDED: UnknownSecurityLevelError
// NOT NEEDED: UnknownStorageKeyRequirementsError
// NOT NEEDED: UnknownTradeModeError
// NOT NEEDED: UnknownTransferableTypeError
// NOT NEEDED: UnsupportedFeatureError
// NOT NEEDED: UnsupportedProtocolVersionError
// NOT NEEDED: UnsupportedVersionError
// NOT NEEDED: UntweakedKeyPair
// NOT NEEDED: UntweakedPublicKey
// NOT NEEDED: Upper
// NOT NEEDED: UpperWriter
// NOT NEEDED: DUPLICATE_UsedKeyMatrix
// NOT NEEDED: ValidationResult
// NOT NEEDED: Validator
// NOT NEEDED: ValidatorSet
// NOT NEEDED: ValidatorSetV0
// NOT NEEDED: ValidatorV0
// NOT NEEDED: ValueError
// NOT NEEDED: ValueMapDeserializer
// NOT NEEDED: VarInt
// NOT NEEDED: Version
// NOT NEEDED: VersionError
// NOT NEEDED: VersionMessage
// NOT NEEDED: Visitor
// NOT NEEDED: VotePollNotAvailableForVotingError
// NOT NEEDED: VotePollNotFoundError
// NOT NEEDED: WPubkeyHash
// NOT NEEDED: WScriptHash
// NOT NEEDED: Weight
// NOT NEEDED: With
// NOT NEEDED: WithdrawalOutputScriptNotAllowedWhenSigningWithOwnerKeyError
// NOT NEEDED: WithdrawalTransactionIndex
// NOT NEEDED: WithdrawalTransactionIndexAndBytes
// NOT NEEDED: Witness
// NOT NEEDED: WitnessCommitment
// NOT NEEDED: WitnessMerkleNode
// NOT NEEDED: WitnessProgram
// NOT NEEDED: WitnessVersion
// NOT NEEDED: Work
// NOT NEEDED: DUPLICATE_WrongPublicKeyPurposeError
// NOT NEEDED: Wtxid
// NOT NEEDED: XpubIdentifier
// NOT NEEDED: YesNoAbstainVoteChoice
