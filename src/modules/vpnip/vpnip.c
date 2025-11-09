#include "common/printing.h"
#include "common/jsonconfig.h"
#include "detection/vpnip/vpnip.h"
#include "modules/vpnip/vpnip.h"
#include "util/stringUtils.h"

#define FF_VPNIP_DISPLAY_NAME "VPN IP"

static void printIp(FFVpnIpResult* ip, FFstrbuf* buffer)
{
    if (ip->ipv4.length)
    {
        ffStrbufAppend(buffer, &ip->ipv4);
    }
    if (ip->ipv6.length)
    {
        if (buffer->length) ffStrbufAppendC(buffer, ' ');
        ffStrbufAppend(buffer, &ip->ipv6);
    }
}

bool ffPrintVpnIp(FFVpnIpOptions* options)
{
    FF_LIST_AUTO_DESTROY results = ffListCreate(sizeof(FFVpnIpResult));

    const char* error = ffDetectVpnIps(options, &results);

    if(error)
    {
        ffPrintError(FF_VPNIP_DISPLAY_NAME, 0, &options->moduleArgs, FF_PRINT_TYPE_DEFAULT, "%s", error);
        return false;
    }

    if(results.length == 0)
    {
        ffPrintError(FF_VPNIP_DISPLAY_NAME, 0, &options->moduleArgs, FF_PRINT_TYPE_DEFAULT, "Failed to detect any IPs for tun0");
        return false;
    }

    FF_STRBUF_AUTO_DESTROY buffer = ffStrbufCreate();

    FF_LIST_FOR_EACH(FFVpnIpResult, ip, results)
    {
        if (buffer.length)
            ffStrbufAppendS(&buffer, " - ");
        printIp(ip, &buffer);
    }

    if(buffer.length > 0)
    {
        ffPrintLogoAndKey(FF_VPNIP_DISPLAY_NAME, 0, &options->moduleArgs, FF_PRINT_TYPE_DEFAULT);
        ffStrbufPutTo(&buffer, stdout);
    }


    FF_LIST_FOR_EACH(FFVpnIpResult, ip, results)
    {
        ffStrbufDestroy(&ip->name);
        ffStrbufDestroy(&ip->ipv4);
        ffStrbufDestroy(&ip->ipv6);
    }

    return true;
}

void ffParseVpnIpJsonObject(FFVpnIpOptions* options, yyjson_val* module)
{
    yyjson_val *key, *val;
    size_t idx, max;
    yyjson_obj_foreach(module, idx, max, key, val)
    {
        if (ffJsonConfigParseModuleArgs(key, val, &options->moduleArgs))
            continue;

        if (unsafe_yyjson_equals_str(key, "showIpv4"))
        {
            if (yyjson_get_bool(val))
                options->showType |= FF_VPNIP_TYPE_IPV4_BIT;
            else
                options->showType &= ~FF_VPNIP_TYPE_IPV4_BIT;
            continue;
        }

        if (unsafe_yyjson_equals_str(key, "showIpv6"))
        {
            if (yyjson_get_bool(val))
                options->showType |= FF_VPNIP_TYPE_IPV6_BIT;
            else
                options->showType &= ~FF_VPNIP_TYPE_IPV6_BIT;
            continue;
        }

        if (unsafe_yyjson_equals_str(key, "showPrefixLen"))
        {
            if (yyjson_get_bool(val))
                options->showType |= FF_VPNIP_TYPE_PREFIX_LEN_BIT;
            else
                options->showType &= ~FF_VPNIP_TYPE_PREFIX_LEN_BIT;
            continue;
        }

        if (unsafe_yyjson_equals_str(key, "namePrefix"))
        {
            ffStrbufSetJsonVal(&options->namePrefix, val);
            continue;
        }

        ffPrintError(FF_VPNIP_MODULE_NAME, 0, &options->moduleArgs, FF_PRINT_TYPE_DEFAULT, "Unknown JSON key %s", unsafe_yyjson_get_str(key));
    }
}

void ffGenerateVpnIpJsonConfig(FFVpnIpOptions* options, yyjson_mut_doc* doc, yyjson_mut_val* module)
{
    ffJsonConfigGenerateModuleArgsConfig(doc, module, &options->moduleArgs);

    yyjson_mut_obj_add_bool(doc, module, "showIpv4", !!(options->showType & FF_VPNIP_TYPE_IPV4_BIT));
    yyjson_mut_obj_add_bool(doc, module, "showIpv6", !!(options->showType & FF_VPNIP_TYPE_IPV6_BIT));
    yyjson_mut_obj_add_bool(doc, module, "showPrefixLen", !!(options->showType & FF_VPNIP_TYPE_PREFIX_LEN_BIT));
    yyjson_mut_obj_add_strbuf(doc, module, "namePrefix", &options->namePrefix);
}

bool ffGenerateVpnIpJsonResult(FF_MAYBE_UNUSED FFVpnIpOptions* options, yyjson_mut_doc* doc, yyjson_mut_val* module)
{
    FF_LIST_AUTO_DESTROY results = ffListCreate(sizeof(FFVpnIpResult));

    const char* error = ffDetectVpnIps(options, &results);

    if(error)
    {
        yyjson_mut_obj_add_str(doc, module, "error", error);
        return false;
    }

    yyjson_mut_val* arr = yyjson_mut_obj_add_arr(doc, module, "result");
    FF_LIST_FOR_EACH(FFVpnIpResult, ip, results)
    {
        yyjson_mut_val* obj = yyjson_mut_arr_add_obj(doc, arr);
        yyjson_mut_obj_add_strbuf(doc, obj, "name", &ip->name);
        if (options->showType & FF_VPNIP_TYPE_IPV4_BIT)
            yyjson_mut_obj_add_strbuf(doc, obj, "ipv4", &ip->ipv4);
        if (options->showType & FF_VPNIP_TYPE_IPV6_BIT)
            yyjson_mut_obj_add_strbuf(doc, obj, "ipv6", &ip->ipv6);
    }

    FF_LIST_FOR_EACH(FFVpnIpResult, ip, results)
    {
        ffStrbufDestroy(&ip->name);
        ffStrbufDestroy(&ip->ipv4);
        ffStrbufDestroy(&ip->ipv6);
    }

    return true;
}

void ffInitVpnIpOptions(FFVpnIpOptions* options)
{
    ffOptionInitModuleArg(&options->moduleArgs, "󰖂");
    options->showType = FF_VPNIP_TYPE_IPV4_BIT | FF_VPNIP_TYPE_IPV6_BIT;
    ffStrbufInit(&options->namePrefix);
}

void ffDestroyVpnIpOptions(FFVpnIpOptions* options)
{
    ffOptionDestroyModuleArg(&options->moduleArgs);
    ffStrbufDestroy(&options->namePrefix);
}

FFModuleBaseInfo ffVpnIpModuleInfo = {
    .name = FF_VPNIP_MODULE_NAME,
    .description = "Show VPN IP address for tun0 interface",
    .initOptions = (void*) ffInitVpnIpOptions,
    .destroyOptions = (void*) ffDestroyVpnIpOptions,
    .parseJsonObject = (void*) ffParseVpnIpJsonObject,
    .printModule = (void*) ffPrintVpnIp,
    .generateJsonResult = (void*) ffGenerateVpnIpJsonResult,
    .generateJsonConfig = (void*) ffGenerateVpnIpJsonConfig,
    .formatArgs = FF_FORMAT_ARG_LIST(((FFModuleFormatArg[]) {
        {"IPv4 address", "ipv4"},
        {"IPv6 address", "ipv6"},
        {"Interface name", "ifname"},
    }))
};
