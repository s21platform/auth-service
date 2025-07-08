# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [api/auth.proto](#api_auth-proto)
    - [CheckEmailAvailabilityIn](#-CheckEmailAvailabilityIn)
    - [CheckEmailAvailabilityOut](#-CheckEmailAvailabilityOut)
    - [LoginRequest](#-LoginRequest)
    - [LoginResponse](#-LoginResponse)
    - [LoginV2In](#-LoginV2In)
    - [LoginV2Out](#-LoginV2Out)
    - [NewUserRegister](#-NewUserRegister)
    - [RefreshAccessTokenIn](#-RefreshAccessTokenIn)
    - [RefreshAccessTokenOut](#-RefreshAccessTokenOut)
    - [RegisterUserIn](#-RegisterUserIn)
    - [SendUserVerificationCodeIn](#-SendUserVerificationCodeIn)
    - [SendUserVerificationCodeOut](#-SendUserVerificationCodeOut)
  
    - [AuthService](#-AuthService)
  
- [Scalar Value Types](#scalar-value-types)



<a name="api_auth-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## api/auth.proto



<a name="-CheckEmailAvailabilityIn"></a>

### CheckEmailAvailabilityIn



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| email | [string](#string) |  |  |






<a name="-CheckEmailAvailabilityOut"></a>

### CheckEmailAvailabilityOut



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| is_available | [bool](#bool) |  |  |






<a name="-LoginRequest"></a>

### LoginRequest
Data for request JWT token for all access in our platform


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| username | [string](#string) |  | username can be just nickname or full email (nickanme@student.21-school.ru) |
| password | [string](#string) |  | password from platform |






<a name="-LoginResponse"></a>

### LoginResponse
response JWT token for access


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| jwt | [string](#string) |  | String with jwt |






<a name="-LoginV2In"></a>

### LoginV2In



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| login | [string](#string) |  |  |
| password | [string](#string) |  |  |






<a name="-LoginV2Out"></a>

### LoginV2Out



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| access_token | [string](#string) |  |  |
| refresh_token | [string](#string) |  |  |






<a name="-NewUserRegister"></a>

### NewUserRegister
kafka contracts


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| uuid | [string](#string) |  |  |
| nickname | [string](#string) |  |  |






<a name="-RefreshAccessTokenIn"></a>

### RefreshAccessTokenIn



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| refresh_token | [string](#string) |  |  |






<a name="-RefreshAccessTokenOut"></a>

### RefreshAccessTokenOut



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| access_token | [string](#string) |  |  |






<a name="-RegisterUserIn"></a>

### RegisterUserIn



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| email | [string](#string) |  |  |
| password | [string](#string) |  |  |
| confirm_password | [string](#string) |  |  |
| code | [string](#string) |  |  |
| code_lookup_uuid | [string](#string) |  | UUID to look up the original verification code in pending_registrations |






<a name="-SendUserVerificationCodeIn"></a>

### SendUserVerificationCodeIn
Data for save in pending table


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| email | [string](#string) |  | email to send code |






<a name="-SendUserVerificationCodeOut"></a>

### SendUserVerificationCodeOut
Response for SendCode


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| uuid | [string](#string) |  | UUID of record from pending table |





 

 

 


<a name="-AuthService"></a>

### AuthService
Service for auth processes

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Login | [.LoginRequest](#LoginRequest) | [.LoginResponse](#LoginResponse) | Login method for requesting access token from edu platform |
| CheckEmailAvailability | [.CheckEmailAvailabilityIn](#CheckEmailAvailabilityIn) | [.CheckEmailAvailabilityOut](#CheckEmailAvailabilityOut) |  |
| SendUserVerificationCode | [.SendUserVerificationCodeIn](#SendUserVerificationCodeIn) | [.SendUserVerificationCodeOut](#SendUserVerificationCodeOut) | Send verification code to email and save data into pending table |
| RegisterUser | [.RegisterUserIn](#RegisterUserIn) | [.google.protobuf.Empty](#google-protobuf-Empty) |  |
| LoginV2 | [.LoginV2In](#LoginV2In) | [.LoginV2Out](#LoginV2Out) |  |
| RefreshAccessToken | [.RefreshAccessTokenIn](#RefreshAccessTokenIn) | [.RefreshAccessTokenOut](#RefreshAccessTokenOut) |  |

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

