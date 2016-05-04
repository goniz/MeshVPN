/***************************************************************************
 *   Copyright (C) 2014 by Tobias Volk                                     *
 *   mail@tobiasvolk.de                                                    *
 *                                                                         *
 *   This program is free software: you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation, either version 3 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 ***************************************************************************/


#ifndef H_CONSOLE
#define H_CONSOLE


#include "map.h"
#include "util.h"


// Global definitions.
#define consoleMAXARGS 10


// The console structures.
struct s_console_args {
    void *arg[consoleMAXARGS];
    int len[consoleMAXARGS];
    int count;
};
struct s_console_command {
    void (*function)(struct s_console_args *);
    struct s_console_args fixed_args;
};
struct s_console {
    struct s_map commanddb;
    char *inbuf;
    char *outbuf;
    char prompt[32];
    int prompt_length;
    int prompt_enabled;
    int buffer_size;
    int inbuf_count;
    int outbuf_start;
    int outbuf_count;
};


// Generate console arguments.
#define consoleArgs0() consoleArgsN(0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)
#define consoleArgs1(arg0) consoleArgsN(1, arg0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)
#define consoleArgs2(arg0, arg1) consoleArgsN(2, arg0, arg1, NULL, NULL, NULL, NULL, NULL, NULL, NULL)
#define consoleArgs3(arg0, arg1, arg2) consoleArgsN(3, arg0, arg1, arg2, NULL, NULL, NULL, NULL, NULL, NULL)
#define consoleArgs4(arg0, arg1, arg2, arg3) consoleArgsN(4, arg0, arg1, arg2, arg3, NULL, NULL, NULL, NULL, NULL)
#define consoleArgs5(arg0, arg1, arg2, arg3, arg4) consoleArgsN(5, arg0, arg1, arg2, arg3, arg4, NULL, NULL, NULL, NULL)
#define consoleArgs6(arg0, arg1, arg2, arg3, arg4, arg5) consoleArgsN(6, arg0, arg1, arg2, arg3, arg4, arg5, NULL, NULL, NULL)
#define consoleArgs7(arg0, arg1, arg2, arg3, arg4, arg5, arg6) consoleArgsN(7, arg0, arg1, arg2, arg3, arg4, arg5, arg6, NULL, NULL)
#define consoleArgs8(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7) consoleArgsN(8, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, NULL)
#define consoleArgs9(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) consoleArgsN(9, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
struct s_console_args consoleArgsN(int argc, void *arg0, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5, void *arg6, void *arg7, void *arg8);

// Register a new command. NULL arguments will be replaced by console input.
#define consoleRegisterCommand(console, name, function, args) consoleRegisterCommandN(console, name, strlen(name), function, args)
int consoleRegisterCommandN(struct s_console *console, const char *name, const int namelen, void (*function)(struct s_console_args *), struct s_console_args args);

// Remove a command.
#define consoleUnregisterCommand(console, name) consoleUnregisterCommandN(console, name, strlen(name))
int consoleUnregisterCommandN(struct s_console *console, const char *name, const int namelen);

// Find the function that belongs to the command name.
#define consoleGetCommand(console, name) consoleGetCommandN(console, name, strlen(name))
struct s_console_command *consoleGetCommandN(struct s_console *console, const char *name, const int namelen);

// Send data to the console output.
int consoleOut(struct s_console *console, const char *data, const int datalen);

// Send the prompt to the console output
int consolePrompt(struct s_console *console);

// Send a newline to the console output
int consoleNL(struct s_console *console);

// Get console prompt status.
int consoleGetPromptStatus(struct s_console *console);

// Set console prompt status.
void consoleSetPromptStatus(struct s_console *console, const int status);

// Set up the console prompt.
#define consoleSetPrompt(console, prompt) consoleSetPromptN(console, prompt, strlen(prompt))
int consoleSetPromptN(struct s_console *console, const char *prompt, const int prompt_length);

// Send a message to the console output.
#define consoleMsg(console, msg) consoleMsgN(console, msg, strlen(msg))
int consoleMsgN(struct s_console *console, const char *msg, const int msglen);

// Process an input line.
void consoleProcessLine(struct s_console *console);


// Write to the console.
int consoleWrite(struct s_console *console, const char *input, const int length);

// Read console output.
int consoleRead(struct s_console *console, char *output, const int length);

// Initialize the console.
void consoleInit(struct s_console *console);

// Create a console.
int consoleCreate(struct s_console *console, const int db_size, const int key_size, const int buffer_size) ;

// Destroy a console.
int consoleDestroy(struct s_console *console);

// print table of active peers
void printActivePeerTable();

// print NodeDB
void printNodeDB();

// print RelayDB
void printRelayDB();

// print table of mac addrs
void printMacTable();

// print table of ndp cache
void printNDPTable();

// parse command
void decodeConsole(char *cmd, int cmdlen);

#endif // F_CONSOLE_C
