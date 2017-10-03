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


#ifndef F_SECCOMP_C
#define F_SECCOMP_C


#ifdef HAVE_LIBSECCOMP

#include <seccomp.h>
#include "platform.h"
#include "logging.h"
#include <signal.h>
#include <errno.h>
#include <stdio.h>


// Defines and loads seccomp filter. Returns 1 on success.
static int seccompEnableDo(scmp_filter_ctx ctx) {
	if(ctx == NULL) { return 0; }
	if(seccomp_reset(ctx, SCMP_ACT_KILL) != 0) { return 0; }

	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) != 0) { return 0; }
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) != 0) { return 0; }
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0) != 0) { return 0; }
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0) != 0) { return 0; }

	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(time), 0) != 0) { return 0; }

	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(select), 0) != 0) { return 0; }
#ifdef __NR__newselect
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(_newselect), 0) != 0) { return 0; }
#endif

#ifdef __NR_sigreturn
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigreturn), 0) != 0) { return 0; }
#endif
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0) != 0) { return 0; }
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(restart_syscall), 0) != 0) { return 0; }

	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0) != 0) { return 0; }
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) != 0) { return 0; }
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) != 0) { return 0; }

	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0) != 0) { return 0; }
	if(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(munmap), 0) != 0) { return 0; }

	if(seccomp_load(ctx) != 0) { return 0; }
	return 1;
}


// Enables seccomp filtering. Returns 1 on success.
int seccompEnable() {
	int enabled;
	scmp_filter_ctx filter;
	filter = seccomp_init(SCMP_ACT_KILL);
	if(filter == NULL) {
		return 0;
	}

	enabled = seccompEnableDo(filter);
	seccomp_release(filter);
	return enabled;
}

#else


// No seccomp support.
int seccompEnable() {
	msg("Seccomp support is not enable. Use SECCOMP_ENABLE during build");
	return 0;
}


#endif


#endif // F_SECCOMP_C
