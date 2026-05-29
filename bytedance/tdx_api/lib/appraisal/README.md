# TDX Quote Appraisal

This is a Cython extension for Intel TDX/SGX Quote Verification and Appraisal. It provides a Pythonic wrapper around the Intel DCAP libraries, allowing Python applications to easily verify and appraise execution environments.

## Features

- **Quote Verification**: Wraps `tee_verify_quote_qvt` for checking quote validity and retrieving the verification JWT block.
- **Appraisal**: Includes `tee_appraise_verification_token` logic, `tee_authenticate_appraisal_result`, and `tee_authenticate_policy_owner`.
- **DCAP Adaptability**: Compatible with DCAP < 1.22 and DCAP 1.22+ new APIs.
- Supports both **SGX** and **TDX** quote types.

## Dependencies

- Python 3.x
- Cython
- Intel SGX SDK / DCAP Libraries (`sgx_dcap_quoteverify`, `sgx_urts`)

Ensure you have the Intel SGX SDK installed on your system. By default, it expects the SDK to be at `/opt/intel/sgxsdk`, but you can override this by setting the `SGX_SDK` environment variable.

## Build Instructions

To compile the Cython extension:

```bash
python setup.py build_ext --inplace
```

This will produce the compiled shared library (e.g. `quote_appraisal.cpython-312-x86_64-linux-gnu.so`) in the current directory, which can be imported directly into Python.

## Usage

You can use the high-level `ecdsa_quote_verify` function for typical flows, or call the lower-level wrapper functions independently.

### High-Level API

```python
import quote_appraisal

# Load requisite files
quote_data = open('quote.dat', 'rb').read()
tenant_policy = b"..." # Load policy
platform_policy = b"..." # Load policy
policy_keys = [b"..."] # Load public keys

# Execute complete ECDSA verification pipeline
result = quote_appraisal.ecdsa_quote_verify(
    quote_data=quote_data,
    tenant_policy=tenant_policy,
    platform_policy=platform_policy,
    policy_keys=policy_keys,
    verbose=True
)

if result['overall_success']:
    print("Quote verified completely!")
else:
    print(f"Verification failed: {result['error']}")
```

### Low-Level API

For granular control, you can use:
- `quote_appraisal.verify_quote_qvt(bytes quote_data)`
- `quote_appraisal.appraise_verification_token(bytes jwt_token, list policy_files, time_t check_date=0)`
- `quote_appraisal.authenticate_appraisal_result(bytes appraisal_result, tenant_policy, platform_policy=None)`
- `quote_appraisal.authenticate_policy_owner(bytes quote_data, bytes appraisal_result, list policy_keys)`

## Errors

The module raises `quote_appraisal.QuoteVerifyError` for verification, appraisal, and authentication failures natively sourced from Intel DCAP.
