import type { JsonValue } from "@protobuf-ts/runtime";
import type { JsonReadOptions } from "@protobuf-ts/runtime";
import type { JsonWriteOptions } from "@protobuf-ts/runtime";
import { MessageType } from "@protobuf-ts/runtime";
/**
 * Wrapper message for `double`.
 *
 * The JSON representation for `DoubleValue` is JSON number.
 *
 * @generated from protobuf message google.protobuf.DoubleValue
 */
export interface DoubleValue {
    /**
     * The double value.
     *
     * @generated from protobuf field: double value = 1;
     */
    value: number;
}
/**
 * Wrapper message for `float`.
 *
 * The JSON representation for `FloatValue` is JSON number.
 *
 * @generated from protobuf message google.protobuf.FloatValue
 */
export interface FloatValue {
    /**
     * The float value.
     *
     * @generated from protobuf field: float value = 1;
     */
    value: number;
}
/**
 * Wrapper message for `int64`.
 *
 * The JSON representation for `Int64Value` is JSON string.
 *
 * @generated from protobuf message google.protobuf.Int64Value
 */
export interface Int64Value {
    /**
     * The int64 value.
     *
     * @generated from protobuf field: int64 value = 1;
     */
    value: bigint;
}
/**
 * Wrapper message for `uint64`.
 *
 * The JSON representation for `UInt64Value` is JSON string.
 *
 * @generated from protobuf message google.protobuf.UInt64Value
 */
export interface UInt64Value {
    /**
     * The uint64 value.
     *
     * @generated from protobuf field: uint64 value = 1;
     */
    value: bigint;
}
/**
 * Wrapper message for `int32`.
 *
 * The JSON representation for `Int32Value` is JSON number.
 *
 * @generated from protobuf message google.protobuf.Int32Value
 */
export interface Int32Value {
    /**
     * The int32 value.
     *
     * @generated from protobuf field: int32 value = 1;
     */
    value: number;
}
/**
 * Wrapper message for `uint32`.
 *
 * The JSON representation for `UInt32Value` is JSON number.
 *
 * @generated from protobuf message google.protobuf.UInt32Value
 */
export interface UInt32Value {
    /**
     * The uint32 value.
     *
     * @generated from protobuf field: uint32 value = 1;
     */
    value: number;
}
/**
 * Wrapper message for `bool`.
 *
 * The JSON representation for `BoolValue` is JSON `true` and `false`.
 *
 * @generated from protobuf message google.protobuf.BoolValue
 */
export interface BoolValue {
    /**
     * The bool value.
     *
     * @generated from protobuf field: bool value = 1;
     */
    value: boolean;
}
/**
 * Wrapper message for `string`.
 *
 * The JSON representation for `StringValue` is JSON string.
 *
 * @generated from protobuf message google.protobuf.StringValue
 */
export interface StringValue {
    /**
     * The string value.
     *
     * @generated from protobuf field: string value = 1;
     */
    value: string;
}
/**
 * Wrapper message for `bytes`.
 *
 * The JSON representation for `BytesValue` is JSON string.
 *
 * @generated from protobuf message google.protobuf.BytesValue
 */
export interface BytesValue {
    /**
     * The bytes value.
     *
     * @generated from protobuf field: bytes value = 1;
     */
    value: Uint8Array;
}
declare class DoubleValue$Type extends MessageType<DoubleValue> {
    constructor();
    /**
     * Encode `DoubleValue` to JSON number.
     */
    internalJsonWrite(message: DoubleValue, options: JsonWriteOptions): JsonValue;
    /**
     * Decode `DoubleValue` from JSON number.
     */
    internalJsonRead(json: JsonValue, options: JsonReadOptions, target?: DoubleValue): DoubleValue;
}
/**
 * @generated MessageType for protobuf message google.protobuf.DoubleValue
 */
export declare const DoubleValue: DoubleValue$Type;
declare class FloatValue$Type extends MessageType<FloatValue> {
    constructor();
    /**
     * Encode `FloatValue` to JSON number.
     */
    internalJsonWrite(message: FloatValue, options: JsonWriteOptions): JsonValue;
    /**
     * Decode `FloatValue` from JSON number.
     */
    internalJsonRead(json: JsonValue, options: JsonReadOptions, target?: FloatValue): FloatValue;
}
/**
 * @generated MessageType for protobuf message google.protobuf.FloatValue
 */
export declare const FloatValue: FloatValue$Type;
declare class Int64Value$Type extends MessageType<Int64Value> {
    constructor();
    /**
     * Encode `Int64Value` to JSON string.
     */
    internalJsonWrite(message: Int64Value, options: JsonWriteOptions): JsonValue;
    /**
     * Decode `Int64Value` from JSON string.
     */
    internalJsonRead(json: JsonValue, options: JsonReadOptions, target?: Int64Value): Int64Value;
}
/**
 * @generated MessageType for protobuf message google.protobuf.Int64Value
 */
export declare const Int64Value: Int64Value$Type;
declare class UInt64Value$Type extends MessageType<UInt64Value> {
    constructor();
    /**
     * Encode `UInt64Value` to JSON string.
     */
    internalJsonWrite(message: UInt64Value, options: JsonWriteOptions): JsonValue;
    /**
     * Decode `UInt64Value` from JSON string.
     */
    internalJsonRead(json: JsonValue, options: JsonReadOptions, target?: UInt64Value): UInt64Value;
}
/**
 * @generated MessageType for protobuf message google.protobuf.UInt64Value
 */
export declare const UInt64Value: UInt64Value$Type;
declare class Int32Value$Type extends MessageType<Int32Value> {
    constructor();
    /**
     * Encode `Int32Value` to JSON string.
     */
    internalJsonWrite(message: Int32Value, options: JsonWriteOptions): JsonValue;
    /**
     * Decode `Int32Value` from JSON string.
     */
    internalJsonRead(json: JsonValue, options: JsonReadOptions, target?: Int32Value): Int32Value;
}
/**
 * @generated MessageType for protobuf message google.protobuf.Int32Value
 */
export declare const Int32Value: Int32Value$Type;
declare class UInt32Value$Type extends MessageType<UInt32Value> {
    constructor();
    /**
     * Encode `UInt32Value` to JSON string.
     */
    internalJsonWrite(message: UInt32Value, options: JsonWriteOptions): JsonValue;
    /**
     * Decode `UInt32Value` from JSON string.
     */
    internalJsonRead(json: JsonValue, options: JsonReadOptions, target?: UInt32Value): UInt32Value;
}
/**
 * @generated MessageType for protobuf message google.protobuf.UInt32Value
 */
export declare const UInt32Value: UInt32Value$Type;
declare class BoolValue$Type extends MessageType<BoolValue> {
    constructor();
    /**
     * Encode `BoolValue` to JSON bool.
     */
    internalJsonWrite(message: BoolValue, options: JsonWriteOptions): JsonValue;
    /**
     * Decode `BoolValue` from JSON bool.
     */
    internalJsonRead(json: JsonValue, options: JsonReadOptions, target?: BoolValue): BoolValue;
}
/**
 * @generated MessageType for protobuf message google.protobuf.BoolValue
 */
export declare const BoolValue: BoolValue$Type;
declare class StringValue$Type extends MessageType<StringValue> {
    constructor();
    /**
     * Encode `StringValue` to JSON string.
     */
    internalJsonWrite(message: StringValue, options: JsonWriteOptions): JsonValue;
    /**
     * Decode `StringValue` from JSON string.
     */
    internalJsonRead(json: JsonValue, options: JsonReadOptions, target?: StringValue): StringValue;
}
/**
 * @generated MessageType for protobuf message google.protobuf.StringValue
 */
export declare const StringValue: StringValue$Type;
declare class BytesValue$Type extends MessageType<BytesValue> {
    constructor();
    /**
     * Encode `BytesValue` to JSON string.
     */
    internalJsonWrite(message: BytesValue, options: JsonWriteOptions): JsonValue;
    /**
     * Decode `BytesValue` from JSON string.
     */
    internalJsonRead(json: JsonValue, options: JsonReadOptions, target?: BytesValue): BytesValue;
}
/**
 * @generated MessageType for protobuf message google.protobuf.BytesValue
 */
export declare const BytesValue: BytesValue$Type;
export {};
