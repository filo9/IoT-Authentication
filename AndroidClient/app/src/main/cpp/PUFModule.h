#ifndef PUF_MODULE_H
#define PUF_MODULE_H

#include "CryptoModule.h"
#include <string>
#include <vector>

namespace PUFModule {

    struct PUFResponse {
        CryptoModule::Bytes response;
        CryptoModule::Bytes helper;
    };

    PUFResponse Enroll(const std::string& challenge);
    CryptoModule::Bytes Reconstruct(const std::string& challenge, const CryptoModule::Bytes& helper);
    CryptoModule::Bytes DeriveKeyFromPUF(const CryptoModule::Bytes& pufResponse);

} // namespace PUFModule

#endif // PUF_MODULE_H
