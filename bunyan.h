/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#if !defined(_BUNYAN_H)
#define _BUNYAN_H

enum bunyan_log_level {
	TRACE = 10,
	DEBUG = 20,
	INFO = 30,
	WARN = 40,
	ERROR = 50,
	FATAL = 60
};

enum bunyan_arg_type {
	BNY_STRING,
	BNY_INT,
	BNY_NVLIST
};

void bunyan_init(void);
void bunyan_set_name(const char *name);
void bunyan_log(enum bunyan_log_level level, const char *msg, ...);
void bunyan_set(const char *name1, enum bunyan_arg_type typ1, ...);

#endif
