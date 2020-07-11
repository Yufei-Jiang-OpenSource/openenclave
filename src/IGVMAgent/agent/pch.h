/*++

Copyright (c) Microsoft Corporation

Module Name:

    pch.h

Abstract:

    Precompiled header file for IGVM Agent
--*/

#pragma once

#pragma warning(push)
#pragma warning(disable:4200) // zero length array

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#include <hcl/VbsVmCrypto.h>
#include <common/Base64.h>
#include <common/Base64Decode.h>
#include <common/Logger.h>
#include <vector>
#include <wil/resource.h>
#include <gsl/gsl>
#include <cpprest/http_client.h>
#include <cpprest/json.h>
#include <clients/aad_client.h>
#include <clients/maa_client.h>
#include <clients/skr_client.h>

#include "IGVmAgent.h"
#include "igvmagentrpc.h"

#pragma warning(pop)
