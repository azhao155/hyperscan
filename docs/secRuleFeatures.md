SecRule language features we should support. The following list is based on the reference manual.

| Directive                        | Will supoprt     | Notes |
|----------------------------------|------------------|-------|
| SecAction                        | Yes              | Basic functionality. |
| SecComponentSignature            | Yes              | Useful for parity with logging. |
| SecMarker                        | Yes              | Basic functionality. |
| SecRule                          | Yes              | Basic functionality. |
| SecCollectionTimeout             | Maybe            | Possibly support. May not be useful, as we are considering dos protection as a separate engine. |
| SecDefaultAction                 | Maybe            | Possibly support if ever used in CRS. |
| SecRequestBodyAccess             | Maybe            | Maybe just build it into the engine directly rather than read it from SecRules file. |
| SecRequestBodyLimit              | Maybe            | Maybe just build it into the engine directly rather than read it from SecRules file. |
| SecRequestBodyLimitAction        | Maybe            | Maybe just build it into the engine directly rather than read it from SecRules file. |
| SecRequestBodyNoFilesLimit       | Maybe            | Maybe just build it into the engine directly rather than read it from SecRules file. |
| SecResponseBodyAccess            | Maybe            | Maybe just build it into the engine directly rather than read it from SecRules file. |
| SecResponseBodyLimit             | Maybe            | Maybe just build it into the engine directly rather than read it from SecRules file. |
| SecResponseBodyLimitAction       | Maybe            | Maybe just build it into the engine directly rather than read it from SecRules file. |
| SecRuleEngine                    | Maybe            | Maybe just build it into the engine directly rather than read it from SecRules file. |
| SecRuleRemoveById                | Maybe            | Maybe just build it into the engine directly rather than read it from SecRules file. |
| SecRuleUpdateTargetById          | Maybe            | Maybe just build it into the engine directly rather than read it from SecRules file. |
| SecRuleUpdateTargetByMsg         | Maybe            | Maybe just build it into the engine directly rather than read it from SecRules file. |
| SecUnicodeCodePage               | Maybe            | Maybe just build it into the engine directly rather than read it from SecRules file. |
| SecUnicodeMapFile                | Maybe            | Maybe just build it into the engine directly rather than read it from SecRules file. |
| SecArgumentSeparator             | No               | Too obscure. |
| SecAuditEngine                   | No               | ModSec specific logging related. |
| SecAuditLog                      | No               | ModSec specific logging related. |
| SecAuditLog2                     | No               | ModSec specific logging related. |
| SecAuditLogDirMode               | No               | ModSec specific logging related. |
| SecAuditLogFileMode              | No               | ModSec specific logging related. |
| SecAuditLogFormat                | No               | ModSec specific logging related. |
| SecAuditLogParts                 | No               | ModSec specific logging related. |
| SecAuditLogRelevantStatus        | No               | ModSec specific logging related. |
| SecAuditLogStorageDir            | No               | ModSec specific logging related. |
| SecAuditLogType                  | No               | ModSec specific logging related. |
| SecCacheTransformations          | No               | ModSec specific engine tweak. |
| SecChrootDir                     | No               | ModSec specific engine tweak. |
| SecConnEngine                    | No               | We are considering dos protection as a separate engine. |
| SecConnReadStateLimit            | No               | ModSec specific engine tweak. But we should probably build similar functionality into our engine. |
| SecConnWriteStateLimit           | No               | ModSec specific engine tweak. But we should probably build similar functionality into our engine. |
| SecContentInjection              | No               | This relates to response editing. We probably only want to support request scanning. |
| SecCookieFormat                  | No               | Too obscure. |
| SecCookieV0Separator             | No               | Too obscure. |
| SecDataDir                       | No               | ModSec specific engine tweak. |
| SecDebugLog                      | No               | ModSec specific logging related. |
| SecDebugLogLevel                 | No               | ModSec specific logging related. |
| SecDisableBackendCompression     | No               | We probably only want to support request scanning. |
| SecGeoLookupDb                   | No               | We are implementing geo restrictions separately. |
| SecGsbLookupDb                   | No               | Interesting. If we want Google Safe Browsing, we will probably implement separately. |
| SecGuardianLog                   | No               | Interesting feature. But not useful as we will do DOS protection seperately. |
| SecHashEngine                    | No               | Too obscure. |
| SecHashKey                       | No               | Too obscure. |
| SecHashMethodPm                  | No               | Too obscure. |
| SecHashMethodRx                  | No               | Too obscure. |
| SecHashParam                     | No               | Too obscure. |
| SecHttpBlKey                     | No               | We are implementing blacklist checking separately. |
| SecInterceptOnError              | No               | ModSec specific engine tweak. |
| SecPcreMatchLimit                | No               | ModSec specific engine tweak. |
| SecPcreMatchLimitRecursion       | No               | ModSec specific engine tweak. |
| SecPdfProtect                    | No               | Interesting feature. Deprecated from ModSec though, so probably too obscure. |
| SecPdfProtectMethod              | No               |  |
| SecPdfProtectSecret              | No               |  |
| SecPdfProtectTimeout             | No               |  |
| SecPdfProtectTimeout             | No               |  |
| SecPdfProtectTokenName           | No               |  |
| SecReadStateLimit                | No               | ModSec specific engine tweak. But we should probably build similar functionality into our engine. |
| SecRemoteRules                   | No               | Too obscure. |
| SecRemoteRulesFailAction         | No               | Too obscure. |
| SecRequestBodyInMemoryLimit      | No               | ModSec specific engine tweak. |
| SecResponseBodyMimeType          | No               | This relates to response scanning. We probably only want to support request scanning. |
| SecResponseBodyMimeTypesClear    | No               |  |
| SecRuleInheritance               | No               | Specific to apache configs. |
| SecRulePerfTime                  | No               | ModSec specific logging related. |
| SecRuleRemoveByMsg               | No               | Too obscure. |
| SecRuleRemoveByTag               | No               | Too obscure. |
| SecRuleScript                    | No               | Too obscure. |
| SecRuleUpdateActionById          | No               | Too obscure. |
| SecRuleUpdateTargetByTag         | No               | Too obscure. |
| SecSensorId                      | No               | ModSec specific logging related. |
| SecServerSignature               | No               | Too obscure. |
| SecStatusEngine                  | No               | ModSec specific engine tweak. |
| SecStreamInBodyInspection        | No               | ModSec specific engine tweak. |
| SecStreamOutBodyInspection       | No               | ModSec specific engine tweak. |
| SecTmpDir                        | No               | ModSec specific engine tweak. |
| SecUploadDir                     | No               | ModSec specific engine tweak. |
| SecUploadFileMode                | No               | ModSec specific engine tweak. |
| SecUploadKeepFiles               | No               | ModSec specific engine tweak. |
| SecWebAppId                      | No               | Interesting. We don't currently really support this scenario though, and CRS doesn't use it. |
| SecWriteStateLimit               | No               | ModSec specific engine tweak. But we should probably build similar functionality into our engine. |
| SecXmlExternalEntity             | No               | Too obscure. |

| Variable                        | Will supoprt    | Notes |
|---------------------------------|-----------------|-------|
| ARGS                            | Yes             | Basic functionality. |
| ARGS_COMBINED_SIZE              | Yes             | Used in CRS |
| ARGS_GET                        | Yes             | Basic functionality. |
| ARGS_GET_NAMES                  | Yes             | Basic functionality. |
| ARGS_NAMES                      | Yes             | Basic functionality. |
| AUTH_TYPE                       | Yes             | Used in CRS |
| FILES                           | Yes             | Used in CRS |
| FILES_COMBINED_SIZE             | Yes             | Used in CRS |
| FILES_NAMES                     | Yes             | Used in CRS |
| MATCHED_VAR                     | Yes             | Basic functionality. |
| MATCHED_VAR_NAME                | Yes             | Basic functionality. |
| MATCHED_VARS                    | Yes             | Basic functionality. |
| MATCHED_VARS_NAMES              | Yes             | Basic functionality. |
| MULTIPART_STRICT_ERROR          | Yes             | Used in CRS |
| MULTIPART_UNMATCHED_BOUNDARY    | Yes             | Used in CRS |
| QUERY_STRING                    | Yes             | Basic functionality. |
| REMOTE_ADDR                     | Yes             | Basic functionality. |
| REQBODY_ERROR                   | Yes             | Used in CRS |
| REQBODY_ERROR_MSG               | Yes             | Used in CRS |
| REQBODY_PROCESSOR               | Yes             | Used in CRS |
| REQUEST_BASENAME                | Yes             | Used in CRS |
| REQUEST_BODY                    | Yes             | Basic functionality. |
| REQUEST_COOKIES                 | Yes             | Basic functionality. |
| REQUEST_COOKIES_NAMES           | Yes             | Basic functionality. |
| REQUEST_FILENAME                | Yes             | Basic functionality. |
| REQUEST_HEADERS                 | Yes             | Basic functionality. |
| REQUEST_HEADERS_NAMES           | Yes             | Basic functionality. |
| REQUEST_LINE                    | Yes             | Basic functionality. |
| REQUEST_METHOD                  | Yes             | Basic functionality. |
| REQUEST_PROTOCOL                | Yes             | Basic functionality. |
| REQUEST_URI                     | Yes             | Basic functionality. |
| REQUEST_URI_RAW                 | Yes             | Basic functionality. |
| TX                              | Yes             | Basic functionality. |
| XML                             | Yes             | Basic functionality. |
| ARGS_POST                       | Maybe           | Not used in CRS |
| ARGS_POST_NAMES                 | Maybe           | Not used in CRS |
| DURATION                        | Maybe           | Used in CRS, but only to generate a pseudorandom number for the A/B test feature we are not using |
| GEO                             | Maybe           | Used in CRS, but we want to make a separate geo module... |
| UNIQUE_ID                       | Maybe           | Used in CRS, but only to generate a pseudorandom number for the A/B test feature we are not using |
| WEBSERVER_ERROR_LOG             | Maybe           | Used in CRS, but awkward, and maybe not worth including. |
| ENV                             | No              | Not used in CRS |
| FILES_SIZES                     | No              | Not used in CRS |
| FILES_TMP_CONTENT               | No              | Not used in CRS |
| FULL_REQUEST                    | No              | Not used in CRS |
| FULL_REQUEST_LENGTH             | No              | Not used in CRS |
| HIGHEST_SEVERITY                | No              | Not used in CRS |
| INBOUND_DATA_ERROR              | No              | Not used in CRS |
| MODSEC_BUILD                    | No              | Not used in CRS |
| MULTIPART_CRLF_LF_LINES         | No              | Not used in CRS |
| MULTIPART_FILENAME              | No              | Not used in CRS |
| MULTIPART_NAME                  | No              | Not used in CRS |
| OUTBOUND_DATA_ERROR             | No              | Not used in CRS |
| PATH_INFO                       | No              | Not used in CRS |
| PERF_ALL                        | No              | Not used in CRS |
| PERF_COMBINED                   | No              | Not used in CRS |
| PERF_GC                         | No              | Not used in CRS |
| PERF_LOGGING                    | No              | Not used in CRS |
| PERF_PHASE1                     | No              | Not used in CRS |
| PERF_PHASE2                     | No              | Not used in CRS |
| PERF_PHASE3                     | No              | Not used in CRS |
| PERF_PHASE4                     | No              | Not used in CRS |
| PERF_PHASE5                     | No              | Not used in CRS |
| PERF_RULES                      | No              | Not used in CRS |
| PERF_SREAD                      | No              | Not used in CRS |
| PERF_SWRITE                     | No              | Not used in CRS |
| REMOTE_HOST                     | No              | Not used in CRS. Would require reverse dns lookups. |
| REMOTE_PORT                     | No              | Not used in CRS. |
| REMOTE_USER                     | No              | Not used in CRS. |
| REQUEST_BODY_LENGTH             | No              | Not used in CRS |
| RESPONSE_BODY                   | No              | We are not dealing with response inspection yet. |
| RESPONSE_CONTENT_LENGTH         | No              | We are not dealing with response inspection yet. |
| RESPONSE_CONTENT_TYPE           | No              | We are not dealing with response inspection yet. |
| RESPONSE_HEADERS                | No              | We are not dealing with response inspection yet. |
| RESPONSE_HEADERS_NAMES          | No              | We are not dealing with response inspection yet. |
| RESPONSE_PROTOCOL               | No              | We are not dealing with response inspection yet. |
| RESPONSE_STATUS                 | No              | We are not dealing with response inspection yet. |
| RULE                            | No              | Not used in CRS |
| SCRIPT_BASENAME                 | No              | Not used in CRS |
| SCRIPT_FILENAME                 | No              | Not used in CRS |
| SCRIPT_GID                      | No              | Not used in CRS |
| SCRIPT_GROUPNAME                | No              | Not used in CRS |
| SCRIPT_MODE                     | No              | Not used in CRS |
| SCRIPT_UID                      | No              | Not used in CRS |
| SCRIPT_USERNAME                 | No              | Not used in CRS |
| SDBM_DELETE_ERROR               | No              | Not used in CRS |
| SERVER_ADDR                     | No              | Not used in CRS |
| SERVER_NAME                     | No              | Not used in CRS |
| SESSION                         | No              | Not used in CRS |
| SESSIONID                       | No              | Not used in CRS |
| STATUS_LINE                     | No              | Not used in CRS |
| STREAM_INPUT_BODY               | No              | Not used in CRS |
| STREAM_OUTPUT_BODY              | No              | Not used in CRS |
| TIME                            | No              | Not used in CRS |
| TIME_DAY                        | No              | Not used in CRS |
| TIME_EPOCH                      | No              | Not used in CRS |
| TIME_HOUR                       | No              | Not used in CRS |
| TIME_MIN                        | No              | Not used in CRS |
| TIME_MON                        | No              | Not used in CRS |
| TIME_SEC                        | No              | Not used in CRS |
| TIME_WDAY                       | No              | Not used in CRS |
| TIME_YEAR                       | No              | Not used in CRS |
| URLENCODED_ERROR                | No              | Not used in CRS |
| USERAGENT_IP                    | No              | Not used in CRS |
| USERID                          | No              | Not used in CRS |
| WEBAPPID                        | No              | Not used in CRS |

| Action                          | Will supoprt        | Notes |
|---------------------------------|---------------------|------- |
| block                           | Yes                 | Basic functionality. |
| capture                         | Yes                 | Basic functionality. |
| chain                           | Yes                 | Basic functionality. |
| deny                            | Yes                 | Basic functionality. |
| drop                            | Yes                 | Basic functionality. |
| expirevar                       | Yes                 | Used in CRS |
| id                              | Yes                 | Basic functionality. |
| initcol                         | Yes                 | Basic functionality. |
| log                             | Yes                 | Basic functionality. |
| logdata                         | Yes                 | Basic functionality. |
| msg                             | Yes                 | Basic functionality. |
| multiMatch                      | Yes                 | Basic functionality. This is going to be expensive. |
| pass                            | Yes                 | Basic functionality. |
| setvar                          | Yes                 | Basic functionality. |
| skipAfter                       | Yes                 | Basic functionality. |
| t:cmdLine                       | Yes                 | Used in CRS |
| t:compressWhitespace            | Yes                 | Used in CRS |
| t:cssDecode                     | Yes                 | Used in CRS |
| t:hexEncode                     | Yes                 | Used in CRS |
| t:htmlEntityDecode              | Yes                 | Basic functionality. |
| t:jsDecode                      | Yes                 | Basic functionality. |
| t:length                        | Yes                 | Basic functionality. |
| t:lowercase                     | Yes                 | Basic functionality. |
| t:none                          | Yes                 | Used in CRS |
| t:normalisePath                 | Yes                 | Used in CRS |
| t:normalisePathWin              | Yes                 | Used in CRS |
| t:normalizePath                 | Yes                 | Used in CRS |
| t:normalizePathWin              | Yes                 | Used in CRS |
| t:removeComments                | Yes                 | Used in CRS |
| t:removeNulls                   | Yes                 | Basic functionality. |
| t:removeWhitespace              | Yes                 | Basic functionality. |
| t:replaceComments               | Yes                 | Used in CRS |
| t:sha1                          | Yes                 | Used in CRS |
| t:urlDecode                     | Yes                 | Basic functionality. |
| t:urlDecodeUni                  | Yes                 | Basic functionality. |
| t:utf8toUnicode                 | Yes                 | Basic functionality. |
| ctl:forceRequestBodyVariable    | Yes, maybe no-op    | Specific to how ModSec works internally |
| maturity                        | Yes, maybe no-op    | Basic functionality. We are not using this in our logs. |
| accuracy                        | Yes, no-op          | Used in CRS. We are not using this in our logs. |
| auditlog                        | Yes, no-op          | Used in CRS. |
| ctl:auditEngine                 | Yes, no-op          | Specific to ModSec's logging system |
| ctl:auditLogParts               | Yes, no-op          | Specific to ModSec's logging system |
| noauditlog                      | Yes, no-op          | Specific to ModSec's logging system |
| nolog                           | Yes, no-op          | Specific to ModSec's logging system |
| phase                           | Yes, no-op          | We don't need phases. |
| rev                             | Yes, no-op          | Specific to ModSec's logging system |
| severity                        | Yes, no-op          | Specific to ModSec's logging system |
| tag                             | Yes, no-op          | Specific to ModSec's logging system |
| ver                             | Yes, no-op          | Specific to ModSec's logging system |
| ver                             | Yes, no-op          | Specific to ModSec's logging system |
| allow                           | Maybe               | Basic functionality, but don't think CRS is using it. Maybe we use it in custom rules? |
| ctl:requestBodyAccess           | Maybe               | Used in CRS REQUEST-903.9001-DRUPAL-EXCLUSION-RULES.conf |
| ctl:requestBodyProcessor        | Maybe               | Used in CRS 2 |
| ctl:ruleEngine                  | Maybe               | Is this really useful to do in an action rather than a directive? |
| ctl:ruleRemoveById              | Maybe               | Is this really useful to do in an action rather than a directive? |
| ctl:ruleRemoveTargetById        | Maybe               | Is this really useful to do in an action rather than a directive? |
| ctl:ruleRemoveTargetByTag       | Maybe               | Is this really useful to do in an action rather than a directive? |
| setenv                          | Maybe               | Used in CRS 2, but is this really necessary? |
| status                          | Maybe               | Basic functionality and used in CRS, but just one place. Also, maybe we don't want the SecEngine to have this freedom. |
| append                          | No                  | Not used in CRS |
| ctl:debugLogLevel               | No                  | Not used in CRS |
| ctl:hashEnforcement             | No                  | Not used in CRS |
| ctl:hashEngine                  | No                  | Not used in CRS |
| ctl:requestBodyLimit            | No                  | Not used in CRS |
| ctl:responseBodyAccess          | No                  | Not used in CRS |
| ctl:responseBodyLimit           | No                  | Not used in CRS |
| ctl:ruleRemoveByMsg             | No                  | Not used in CRS |
| ctl:ruleRemoveByTag             | No                  | Not used in CRS |
| ctl:ruleRemoveTargetByMsg       | No                  | Not used in CRS |
| deprecatevar                    | No                  | Not used in CRS |
| exec                            | No                  | Not used in CRS. Besides, this is super expensive! |
| pause                           | No                  | Not used in CRS. |
| prepend                         | No                  | Not used in CRS. |
| proxy                           | No                  | Not used in CRS. |
| redirect                        | No                  | Not used in CRS. |
| sanitiseArg                     | No                  | Not used in CRS. |
| sanitiseMatched                 | No                  | Not used in CRS. |
| sanitiseMatchedBytes            | No                  | Not used in CRS. |
| sanitiseRequestHeader           | No                  | Not used in CRS. |
| setrsc                          | No                  | Not used in CRS. |
| setsid                          | No                  | Not used in CRS. |
| setuid                          | No                  | Not used in CRS. |
| skip                            | No                  | Not used in CRS. |
| t:base64Decode                  | No                  | Not used in CRS |
| t:base64DecodeExt               | No                  | Not used in CRS |
| t:escapeSeqDecode               | No                  | Not used in CRS |
| t:hexDecode                     | No                  | Not used in CRS |
| t:md5                           | No                  | Not used in CRS |
| t:parityEven7bit                | No                  | Not used in CRS |
| t:parityOdd7bit                 | No                  | Not used in CRS |
| t:parityZero7bit                | No                  | Not used in CRS |
| t:removeCommentsChar            | No                  | Not used in CRS |
| t:replaceNulls                  | No                  | Not used in CRS |
| t:sqlHexDecode                  | No                  | Not used in CRS |
| t:trim                          | No                  | Not used in CRS |
| t:trimLeft                      | No                  | Not used in CRS |
| t:trimRight                     | No                  | Not used in CRS |
| t:uppercase                     | No                  | Not used in CRS |
| t:urlEncode                     | No                  | Not used in CRS |
| xmlns                           | No                  | Not used in CRS. |

| Operator                        | Will supoprt        | Notes |
|---------------------------------|---------------------|-------|
| beginsWith                      | Yes                 | Basic functionality. |
| contains                        | Yes                 | Basic functionality. |
| containsWord                    | Yes                 | Basic functionality. |
| detectSQLi                      | Yes                 | Used in CRS |
| detectXSS                       | Yes                 | Used in CRS |
| eq                              | Yes                 | Basic functionality. |
| ge                              | Yes                 | Basic functionality. |
| gt                              | Yes                 | Basic functionality. |
| lt                              | Yes                 | Basic functionality. |
| pm                              | Yes                 | Basic functionality. |
| pmf                             | Yes                 | Basic functionality. |
| pmFromFile                      | Yes                 | Basic functionality. |
| rx                              | Yes                 | Basic functionality. |
| streq                           | Yes                 | Basic functionality. |
| strmatch                        | Yes                 | Basic functionality. Is this the same as @pm? |
| validateByteRange               | Yes                 | Used in CRS |
| validateUrlEncoding             | Yes                 | Used in CRS |
| validateUtf8Encoding            | Yes                 | Used in CRS |
| within                          | Yes                 | Basic functionality. |
| geoLookup                       | Maybe               | Used in CRS, but we want to make a separate geo module... |
| ipMatch                         | Maybe               | Basic functionality, and CRS is using it, but only a very little. We use it in custom rules, but maybe we don't want custom to go via the SecRule engine. |
| le                              | Maybe               | Basic functionality, but not used in CRS |
| rbl                             | Maybe               | Used in CRS, but we want to make a separate blacklist module... |
| fuzzyHash                       | No                  | Not used in CRS |
| gsbLookup                       | No                  | Not used in CRS |
| inspectFile                     | No                  | Not used in CRS |
| ipMatchF                        | No                  | Not used in CRS |
| ipMatchFromFile                 | No                  | Not used in CRS |
| noMatch                         | No                  | Not used in CRS |
| rsub                            | No                  | Not used in CRS |
| unconditionalMatch              | No                  | Not used in CRS |
| validateDTD                     | No                  | Not used in CRS |
| validateHash                    | No                  | Not used in CRS |
| validateSchema                  | No                  | Not used in CRS |
| verifyCC                        | No                  | Not used in CRS |
| verifyCPF                       | No                  | Not used in CRS |
| verifySSN                       | No                  | Not used in CRS |
