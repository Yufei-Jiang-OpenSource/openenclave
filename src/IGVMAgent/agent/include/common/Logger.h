//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

#pragma once

#include <stdio.h>
#include <string.h>

namespace agent
{
    enum class LogLevel
    {
        LOG_NONE,
        LOG_INFO,
        LOG_VERBOSE,
        LOG_ERROR
    };
    class Logger
    {
    public:
        inline static LogLevel _level = LogLevel::LOG_VERBOSE;

        static void Log(LogLevel level, const wchar_t* format, ...)
        {
            if (level == LogLevel::LOG_ERROR || level <= _level)
            {
                va_list args;

                va_start(args, format);
                vwprintf(format, args);
                va_end(args);
            }
        }

    private:
        Logger();
    };
};


#define LOG_INFO(_fmt_, ...) agent::Logger::Log(LogLevel::LOG_INFO, _fmt_ L"\n", __VA_ARGS__)
#define LOG_VERBOSE(_fmt_, ...) agent::Logger::Log(LogLevel::LOG_VERBOSE, _fmt_ L"\n", __VA_ARGS__)
#define LOG_ERROR(_fmt_, ...) agent::Logger::Log(LogLevel::LOG_ERROR, L"ERROR: " _fmt_ L"\n", __VA_ARGS__)

#define LOG_STRING(_s_) agent::Logger::Log(LogLevel::LOG_INFO, L"%ws\n", _s_)
