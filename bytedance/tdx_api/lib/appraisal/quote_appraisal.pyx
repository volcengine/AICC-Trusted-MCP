# cython: language_level=3
"""
TDX Quote Verification & Appraisal - Cython Extension
Compatible with DCAP 1.22+ and earlier versions
"""

from libc.stdint cimport uint8_t, uint32_t, uint16_t
from libc.stdlib cimport malloc, free
from libc.time cimport time, time_t
from libc.string cimport memset, memcpy

# check version
cdef extern from "dlfcn.h":
    void* dlsym(void* handle, const char* symbol)
    void* RTLD_DEFAULT

cdef extern from "sgx_dcap_quoteverify.h":
    ctypedef int quote3_error_t

    quote3_error_t tee_verify_quote_qvt(
        const uint8_t *p_quote,
        uint32_t quote_size,
        const void *p_quote_collateral,
        const void *p_tdqe_report_info,
        const void *p_qv_report_info,
        unsigned int *p_jwt_token_size,
        uint8_t **pp_jwt_token
    )
    
    quote3_error_t tee_free_verify_quote_qvt(
        uint8_t *p_jwt_token,
        unsigned int *p_jwt_token_size
    )

cdef extern from "sgx_dcap_qal.h":
    ctypedef enum tee_platform_policy_type_t:
        DEFAULT_STRICT = 0
        CUSTOMIZED = 1

    ctypedef struct tee_platform_policy_t:
        tee_platform_policy_type_t pt
        const uint8_t* p_policy

    ctypedef struct tee_policy_bundle_t:
        const uint8_t *p_tenant_identity_policy
        tee_platform_policy_t platform_policy
        tee_platform_policy_t tdqe_policy
        tee_platform_policy_t reserved[2]

    ctypedef enum tee_policy_auth_result_t:
        TEE_AUTH_INCOMPLET = -1
        TEE_AUTH_SUCCESS = 0
        TEE_AUTH_FAILURE = 1

    quote3_error_t tee_appraise_verification_token(
        const uint8_t *p_verification_result_token,
        uint8_t **p_qaps,
        uint8_t qaps_count,
        const time_t appraisal_check_date,
        void *p_qae_report_info,
        uint32_t *p_appraisal_result_token_buffer_size,
        uint8_t **p_appraisal_result_token
    )

    quote3_error_t tee_free_appraisal_token(uint8_t *p_appraisal_result_token)

    quote3_error_t tee_authenticate_appraisal_result(
        const uint8_t *p_appraisal_result_token,
        const tee_policy_bundle_t *p_policies,
        tee_policy_auth_result_t *result
    )

    # new version api (DCAP 1.22+)
    quote3_error_t tee_authenticate_policy_owner(
        const uint8_t *p_quote,
        uint32_t quote_size,
        const uint8_t *p_appraisal_result_token,
        const uint8_t **policy_key_list,
        uint32_t list_size,
        const uint8_t *p_td_identity,
        const uint8_t *p_td_tcb_mapping_table,
        tee_policy_auth_result_t *result,
        void *p_qae_report_info
    )


SGX_QUOTE_TYPE = 0x0
TDX_QUOTE_TYPE = 0x81

POLICY_DEFAULT_STRICT = 0
POLICY_CUSTOMIZED = 1

AUTH_SUCCESS = 0
AUTH_FAILURE = 1
AUTH_INCOMPLETE = -1


cdef bint _version_checked = False
cdef bint _has_policy_owner_func = False

class QuoteVerifyError(Exception):
    """Quote verification error"""
    pass

cdef bint check_dcap_version():
    """check DCAP version, make sure it is dupport tee_authenticate_policy_owner or not"""
    global _version_checked, _has_policy_owner_func
    
    if _version_checked:
        return _has_policy_owner_func
    
    cdef void* func_ptr = dlsym(RTLD_DEFAULT, b"tee_authenticate_policy_owner")
    _has_policy_owner_func = (func_ptr != NULL)
    _version_checked = True
    
    return _has_policy_owner_func

def verify_quote_qvt(bytes quote_data):
    cdef:
        const uint8_t* p_quote = <const uint8_t*>quote_data
        uint32_t quote_size = len(quote_data)
        unsigned int jwt_size = 0
        uint8_t* p_jwt = NULL
        quote3_error_t ret
    
    ret = tee_verify_quote_qvt(p_quote, quote_size, NULL, NULL, NULL, &jwt_size, &p_jwt)
    
    if ret != 0 or p_jwt == NULL:
        raise QuoteVerifyError(f"Quote verification failed: 0x{ret:04x}")
    
    try:
        jwt_token = bytes(p_jwt[:jwt_size])
        return jwt_token
    finally:
        tee_free_verify_quote_qvt(p_jwt, &jwt_size)

def appraise_verification_token(bytes jwt_token, list policy_files, time_t check_date=0):
    cdef:
        const uint8_t* p_jwt = <const uint8_t*>jwt_token
        uint8_t** p_qaps = NULL
        uint8_t n_qaps = len(policy_files)
        time_t current_time = check_date if check_date != 0 else time(NULL)
        uint32_t result_size = 0
        uint8_t* p_result = NULL
        quote3_error_t ret
        int i
    
    if n_qaps == 0:
        raise ValueError("At least one policy file is required")
    
    p_qaps = <uint8_t**>malloc(n_qaps * sizeof(uint8_t*))
    if p_qaps == NULL:
        raise MemoryError("Failed to allocate policy array")
    
    policy_refs = []
    
    try:
        for i in range(n_qaps):
            policy = policy_files[i]
            if isinstance(policy, str):
                policy = policy.encode('utf-8')
            if not isinstance(policy, bytes):
                raise TypeError(f"Policy {i} must be bytes or str")
            if not policy.endswith(b'\x00'):
                policy = policy + b'\x00'
            policy_refs.append(policy)
            p_qaps[i] = <uint8_t*>policy
        
        ret = tee_appraise_verification_token(
            p_jwt, p_qaps, n_qaps, current_time, NULL, &result_size, &p_result
        )
        
        if ret != 0 or p_result == NULL:
            raise QuoteVerifyError(f"Appraisal failed: 0x{ret:04x}")
        
        try:
            result_token = bytes(p_result[:result_size])
            return result_token
        finally:
            tee_free_appraisal_token(p_result)
            
    finally:
        free(p_qaps)

def authenticate_appraisal_result(bytes appraisal_result, tenant_policy, platform_policy=None):
    cdef:
        const uint8_t* p_result = <const uint8_t*>appraisal_result
        tee_policy_bundle_t bundle
        tee_policy_auth_result_t auth_result
        quote3_error_t ret
    
    if isinstance(tenant_policy, str):
        tenant_policy = tenant_policy.encode('utf-8')

    if platform_policy is not None and isinstance(platform_policy, str):
        platform_policy = platform_policy.encode('utf-8')
    
    if not tenant_policy.endswith(b'\x00'):
        tenant_policy = tenant_policy + b'\x00'

    if platform_policy is not None and not platform_policy.endswith(b'\x00'):
        platform_policy = platform_policy + b'\x00'
    
    memset(&bundle, 0, sizeof(tee_policy_bundle_t))
    bundle.p_tenant_identity_policy = <const uint8_t*>tenant_policy
    if platform_policy is None:
        bundle.platform_policy.p_policy = NULL
        bundle.platform_policy.pt = DEFAULT_STRICT
    else:
        bundle.platform_policy.p_policy = <const uint8_t*>platform_policy
        bundle.platform_policy.pt = CUSTOMIZED
    
    ret = tee_authenticate_appraisal_result(p_result, &bundle, &auth_result)
    
    if ret != 0:
        raise QuoteVerifyError(f"Authentication failed: 0x{ret:04x}")
    
    return <int>auth_result

def authenticate_policy_owner(bytes quote_data, bytes appraisal_result, list policy_keys):
    cdef:
        const uint8_t* p_quote = <const uint8_t*>quote_data
        uint32_t quote_size = len(quote_data)
        const uint8_t* p_result = <const uint8_t*>appraisal_result
        const uint8_t** p_keys = NULL
        uint32_t key_count = len(policy_keys)
        tee_policy_auth_result_t auth_result
        quote3_error_t ret
        int i
        bint use_new_api = check_dcap_version()
    
    if key_count == 0:
        raise ValueError("At least one policy key is required")
    
    if use_new_api:
        # new version API (DCAP 1.22+)
        return _authenticate_policy_owner_new(quote_data, appraisal_result, policy_keys)
    else:
        # old API (DCAP < 1.22)
        return _authenticate_policy_owner_legacy(appraisal_result, policy_keys)

cdef int _authenticate_policy_owner_new(bytes quote_data, bytes appraisal_result, list policy_keys):
    cdef:
        const uint8_t* p_quote = <const uint8_t*>quote_data
        uint32_t quote_size = len(quote_data)
        const uint8_t* p_result = <const uint8_t*>appraisal_result
        const uint8_t** p_keys = NULL
        uint32_t key_count = len(policy_keys)
        tee_policy_auth_result_t auth_result
        quote3_error_t ret
        int i
    
    p_keys = <const uint8_t**>malloc(key_count * sizeof(uint8_t*))
    if p_keys == NULL:
        raise MemoryError("Failed to allocate key array")
    
    key_refs = []
    
    try:
        for i in range(key_count):
            key = policy_keys[i]
            if isinstance(key, str):
                key = key.encode('utf-8')
            if not isinstance(key, bytes):
                raise TypeError(f"Key {i} must be bytes or str")
            if not key.endswith(b'\x00'):
                key = key + b'\x00'
            key_refs.append(key)
            p_keys[i] = <const uint8_t*>key
        
        ret = tee_authenticate_policy_owner(
            p_quote, quote_size, p_result, p_keys, key_count,
            NULL, NULL, &auth_result, NULL
        )
        
        if ret != 0:
            raise QuoteVerifyError(f"Policy owner authentication failed: 0x{ret:04x}")
        
        return <int>auth_result
        
    finally:
        free(p_keys)

cdef int _authenticate_policy_owner_legacy(bytes appraisal_result, list policy_keys):
    cdef:
        const uint8_t* p_result = <const uint8_t*>appraisal_result
        tee_policy_bundle_t bundle
        tee_policy_auth_result_t auth_result
        quote3_error_t ret
    
    memset(&bundle, 0, sizeof(tee_policy_bundle_t))
    
    if len(policy_keys) > 0:
        key = policy_keys[0]
        if isinstance(key, str):
            key = key.encode('utf-8')
        if not key.endswith(b'\x00'):
            key = key + b'\x00'
        bundle.p_tenant_identity_policy = <const uint8_t*>key
    
    bundle.platform_policy.pt = DEFAULT_STRICT
    
    ret = tee_authenticate_appraisal_result(p_result, &bundle, &auth_result)
    
    if ret != 0:
        raise QuoteVerifyError(f"Legacy policy authentication failed: 0x{ret:04x}")
    
    return <int>auth_result

def check_quote_type(bytes quote_data):
    if len(quote_data) < 8:
        return -1
    
    cdef const uint8_t* p_data = <const uint8_t*>quote_data
    cdef uint32_t quote_type
    
    quote_type = (<const uint32_t*>(p_data + 4))[0]
    
    if quote_type == SGX_QUOTE_TYPE:
        return SGX_QUOTE_TYPE
    elif quote_type == TDX_QUOTE_TYPE:
        return TDX_QUOTE_TYPE
    else:
        return -1

def get_dcap_version_info():
    has_new_api = check_dcap_version()
    return {
        'has_policy_owner_function': has_new_api,
        'api_version': '1.22+' if has_new_api else '<1.22',
        'recommended_function': 'tee_authenticate_policy_owner' if has_new_api else 'tee_authenticate_appraisal_result'
    }

def ecdsa_quote_verify(bytes quote_data, bytes tenant_policy, bytes platform_policy, 
                     list policy_keys, bint verbose=False):
    result = {
        'quote_type': None,
        'verify_success': False,
        'appraisal_success': False,
        'auth_success': False,
        'owner_auth_success': False,
        'dcap_version': None,
        'error': None
    }
    
    try:
        version_info = get_dcap_version_info()
        result['dcap_version'] = version_info
        
        if verbose:
            print(f"Info: DCAP API version - {version_info['api_version']}")
            print(f"Info: Using function - {version_info['recommended_function']}")

        # check Quote type
        quote_type = check_quote_type(quote_data)
        if quote_type == SGX_QUOTE_TYPE:
            result['quote_type'] = 'SGX'
        elif quote_type == TDX_QUOTE_TYPE:
            result['quote_type'] = 'TDX'
        else:
            raise QuoteVerifyError("Unknown quote type")
        
        if verbose:
            print(f"Info: Quote type - {result['quote_type']} quote")
        
        # verify Quote
        jwt_token = verify_quote_qvt(quote_data)
        result['verify_success'] = True
        
        if verbose:
            print("Info: tee_verify_quote_qvt successfully returned")

        # appraisal token
        policies = [tenant_policy, platform_policy]
        appraisal_result = appraise_verification_token(jwt_token, policies)
        result['appraisal_success'] = True
        
        if verbose:
            print("Info: tee_appraise_verification_token successfully returned")
        
        auth_result = authenticate_appraisal_result(appraisal_result, tenant_policy, platform_policy)
        result['auth_result'] = auth_result
        
        if auth_result == AUTH_SUCCESS:
            result['auth_success'] = True
            if verbose:
                print("Info: Policies are authenticated Successfully")
        elif auth_result == AUTH_FAILURE:
            raise QuoteVerifyError("Authentication failures occur in some policies")
        else:
            raise QuoteVerifyError("There are some policies un-authenticated")
        
        owner_result = authenticate_policy_owner(quote_data, appraisal_result, policy_keys)
        result['owner_auth_result'] = owner_result
        
        if owner_result == AUTH_SUCCESS:
            result['owner_auth_success'] = True
            if verbose:
                api_name = "tee_authenticate_policy_owner" if version_info['has_policy_owner_function'] else "legacy authentication"
                print(f"Info: Authenticate policy owner successfully using {api_name}")
        else:
            raise QuoteVerifyError(f"Authenticate policy owner failed: {owner_result}")
        
        result['overall_success'] = True
        return result
        
    except QuoteVerifyError as e:
        result['error'] = str(e)
        result['overall_success'] = False
        return result
    except Exception as e:
        result['error'] = f"Unexpected error: {str(e)}"
        result['overall_success'] = False
        return result
