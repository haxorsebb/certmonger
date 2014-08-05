/*
 * Copyright (C) 2009,2011,2012,2014 Red Hat, Inc.
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <talloc.h>

#include "log.h"
#include "hook.h"
#include "prefs.h"
#include "store.h"
#include "store-int.h"
#include "subproc.h"
#include "tm.h"

enum cm_hook_type {
	cm_hook_pre_save,
	cm_hook_post_save,
	cm_hook_ca_pre_save,
	cm_hook_ca_post_save,
};

struct cm_hook_state {
	struct cm_store_ca *ca;
	struct cm_store_entry *entry;
	struct cm_subproc_state *subproc;
	struct cm_hook_list {
		char *command;
		uid_t uid;
		struct cm_hook_list *next;
	} *hooks;
};

/* Fire off a single subprocess. */
static int
cm_hook_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
	     void *userdata)
{
	char **argv;
	const char *error;
	struct passwd *pwd;
	struct cm_hook_state *state = userdata;

	argv = cm_subproc_parse_args(userdata, state->hooks->command, &error);
	if (error != NULL) {
		cm_log(-2, "Error parsing \"%s\": %s; not running it.\n",
		       state->hooks->command, error);
		return -1;
	}
	pwd = getpwuid(state->hooks->uid);
	if (pwd == NULL) {
		cm_log(-2, "Error on getpwuid(%lu): %s, not running \"%s\".\n",
		       (unsigned long) state->hooks->uid,
		       strerror(errno),
		       state->hooks->command);
		return -1;
	}
	if (initgroups(pwd->pw_name, pwd->pw_gid) == -1) {
		if (getuid() != 0) {
			cm_log(0, "Error on initgroups(%s,%lu): %s, "
			       "continuing and running \"%s\" anyway.\n",
			       pwd->pw_name,
			       (unsigned long) state->hooks->uid,
			       strerror(errno),
			       state->hooks->command);
		} else {
			cm_log(-2, "Error on initgroups(%s,%lu): %s, "
			       "not running \"%s\".\n",
			       pwd->pw_name,
			       (unsigned long) state->hooks->uid,
			       strerror(errno),
			       state->hooks->command);
			return -1;
		}
	}
	if (setregid(pwd->pw_gid, pwd->pw_gid) == -1) {
		cm_log(-2, "Error on setregid(%lu,%lu,%lu): %s, "
		       "not running \"%s\".\n",
		       (unsigned long) pwd->pw_gid,
		       (unsigned long) pwd->pw_gid,
		       (unsigned long) pwd->pw_gid,
		       strerror(errno),
		       state->hooks->command);
		return -1;
	}
	if (setreuid(pwd->pw_uid, pwd->pw_uid) == -1) {
		cm_log(0, "Error on setreuid(%lu,%lu,%lu): %s, "
		       "not running \"%s\".\n",
		       (unsigned long) pwd->pw_uid,
		       (unsigned long) pwd->pw_uid,
		       (unsigned long) pwd->pw_uid,
		       strerror(errno),
		       state->hooks->command);
		return -1;
	}
	cm_subproc_mark_most_cloexec(fd);
	if (execvp(argv[0], argv) == -1) {
		cm_log(0, "Error execvp()ing command \"%s\" (\"%s\"): %s.\n",
		       argv[0], state->hooks->command,
		       strerror(errno));
		return -1;
	}
	return -1;
}

/* Start the command at the head of the hooks list. */
static struct cm_hook_state *
cm_hook_start(struct cm_store_ca *ca, struct cm_store_entry *entry,
	      void *parent, const char *hook_type, struct cm_hook_list *hooks)
{
	struct cm_hook_state *state;

	if (hooks == NULL) {
		cm_log(1, "No hooks set for %s command.\n", hook_type);
		return NULL;
	}

	state = talloc_ptrtype(parent, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->hooks = hooks;
		talloc_steal(state, hooks);
		state->subproc = cm_subproc_start(cm_hook_main, state,
						  ca, entry, state);
		if (state->subproc == NULL) {
			cm_log(0, "Error starting command \"%s\".\n",
			       state->hooks->command);
			talloc_free(state);
			state = NULL;
		}
	} else {
		talloc_free(hooks);
	}
	return state;
}

/* Add a single hook to the list of hooks if it's not already there. */
static struct cm_hook_list *
add_hook(struct cm_hook_list *hooks, const char *hook, const char *hook_uid)
{
	struct cm_hook_list *tmp = NULL, *cur = NULL, *tail = NULL;
	char *p;
	long l;

	if ((hook == NULL) || (hook_uid == NULL)) {
		return hooks;
	}

	p = NULL;
	l = strtol(hook_uid, &p, 10);
	if ((p == NULL) || (*p != '\0')) {
		cm_log(1, "Error parsing \"%s\" as a numeric UID.\n", hook_uid);
		return hooks;
	}

	if (hooks != NULL) {
		cur = hooks;
		tail = cur;
		while (cur != NULL) {
			cm_log(3, "Checking old hook \"%s\" (%lu) \"%s\" (%s).\n",
			       cur->command, (unsigned long) cur->uid,
			       hook, hook_uid);
			if ((cur->uid == l) &&
			    (strcmp(cur->command, hook) == 0)) {
				cm_log(3, "... already in list.\n");
				return hooks;
			}
			cm_log(3, "... not in list.\n");
			tail = cur;
			cur = cur->next;
		}
		tmp = talloc_ptrtype(tail, tmp);
	} else {
		tmp = talloc_ptrtype(NULL, tmp);
	}

	if (tmp == NULL) {
		cm_log(1, "Out of memory parsing hook \"%s\".\n", hook);
		return hooks;
	}
	memset(tmp, 0, sizeof(*tmp));

	tmp->command = talloc_strdup(tmp, hook);
	if (tmp->command == NULL) {
		cm_log(1, "Out of memory parsing hook \"%s\".\n", hook);
		talloc_free(tmp);
		return hooks;
	}
	tmp->uid = l;

	cm_log(3, "Adding hook \"%s\" (%lu).\n", tmp->command,
	       (unsigned long) tmp->uid);

	if (hooks == NULL) {
		return tmp;
	} else {
		tail->next = tmp;
		return hooks;
	}
}

/* Add the right hook if we have a matching save location. */
static struct cm_hook_list *
add_hook_if_match(struct cm_hook_list *hooks, const char *hook,
		  const char *hook_uid, char **list1, char **list2)
{
	int i, j;

	if ((list1 != NULL) && (list2 != NULL)) {
		for (i = 0; list1[i] != NULL; i++) {
			for (j = 0; list2[j] != NULL; j++) {
				if (strcmp(list1[i], list2[j]) == 0) {
					hooks = add_hook(hooks, hook,
							 hook_uid);
				}
			}
		}
	}
	return hooks;
}

/* Walk the list of entries and CAs, and if an entry or CA defines a hook of
 * the specified type, and the locations where that entry or CA will be storing
 * certificates is in one of the passed-in lists of files or databases, add the
 * hook to the list. */
static struct cm_hook_list *
collect_hooks(struct cm_context *context, struct cm_hook_list *hooks,
	      enum cm_hook_type hook_type,
	      struct cm_store_ca *(*get_ca_by_index)(struct cm_context *, int),
	      int (*get_n_cas)(struct cm_context *),
	      struct cm_store_entry *(*get_entry_by_index)(struct cm_context *,
							   int),
	      int (*get_n_entries)(struct cm_context *),
	      char **files, char **nssdbs)
{
	struct cm_store_entry *entry;
	struct cm_store_ca *ca;
	const char *hook = NULL, *hook_uid = NULL;
	int i;

	for (i = 0;
	     (get_n_cas != NULL) && (i < get_n_cas(context));
	     i++) {
		ca = get_ca_by_index(context, i);
		hook = NULL;
		hook_uid = NULL;
		switch (hook_type) {
		case cm_hook_pre_save:
		case cm_hook_ca_pre_save:
			hook = ca->cm_ca_pre_save_command;
			hook_uid = ca->cm_ca_pre_save_uid;
			break;
		case cm_hook_post_save:
		case cm_hook_ca_post_save:
			hook = ca->cm_ca_post_save_command;
			hook_uid = ca->cm_ca_post_save_uid;
			break;
		}
		if ((hook == NULL) || (hook_uid == NULL)) {
			continue;
		}
		hooks = add_hook_if_match(hooks, hook, hook_uid, files,
					  ca->cm_ca_root_cert_store_files);
		hooks = add_hook_if_match(hooks, hook, hook_uid, files,
					  ca->cm_ca_other_root_cert_store_files);
		hooks = add_hook_if_match(hooks, hook, hook_uid, files,
					  ca->cm_ca_other_cert_store_files);
		hooks = add_hook_if_match(hooks, hook, hook_uid, nssdbs,
					  ca->cm_ca_root_cert_store_nssdbs);
		hooks = add_hook_if_match(hooks, hook, hook_uid, nssdbs,
					  ca->cm_ca_other_root_cert_store_nssdbs);
		hooks = add_hook_if_match(hooks, hook, hook_uid, nssdbs,
					  ca->cm_ca_other_cert_store_nssdbs);
	}
	for (i = 0;
	     (get_n_entries != NULL) && (i < get_n_entries(context));
	     i++) {
		entry = get_entry_by_index(context, i);
		hook = NULL;
		hook_uid = NULL;
		switch (hook_type) {
		case cm_hook_pre_save:
		case cm_hook_ca_pre_save:
			hook = entry->cm_pre_certsave_command;
			hook_uid = entry->cm_pre_certsave_uid;
			break;
		case cm_hook_post_save:
		case cm_hook_ca_post_save:
			hook = entry->cm_post_certsave_command;
			hook_uid = entry->cm_post_certsave_uid;
			break;
		}
		if ((hook == NULL) || (hook_uid == NULL)) {
			continue;
		}
		hooks = add_hook_if_match(hooks, hook, hook_uid, files,
					  entry->cm_root_cert_store_files);
		hooks = add_hook_if_match(hooks, hook, hook_uid, files,
					  entry->cm_other_root_cert_store_files);
		hooks = add_hook_if_match(hooks, hook, hook_uid, files,
					  entry->cm_other_cert_store_files);
		hooks = add_hook_if_match(hooks, hook, hook_uid, nssdbs,
					  entry->cm_root_cert_store_nssdbs);
		hooks = add_hook_if_match(hooks, hook, hook_uid, nssdbs,
					  entry->cm_other_root_cert_store_nssdbs);
		hooks = add_hook_if_match(hooks, hook, hook_uid, nssdbs,
					  entry->cm_other_cert_store_nssdbs);
	}
	return hooks;
}

/* Start the pre-save hook. */
struct cm_hook_state *
cm_hook_start_presave(struct cm_store_entry *entry,
		      struct cm_context *context,
		      struct cm_store_ca *(*get_ca_by_index)(struct cm_context *, int),
		      int (*get_n_cas)(struct cm_context *),
		      struct cm_store_entry *(*get_entry_by_index)(struct cm_context *, int),
		      int (*get_n_entries)(struct cm_context *))
{
	struct cm_hook_list *hooks = NULL;

	/* Make a list of the presave hooks from all of the entries and CAs
	 * which reference the storage locations for the certificates that are
	 * referenced by this entry. */
	hooks = collect_hooks(context, hooks, cm_hook_pre_save,
			      get_ca_by_index, get_n_cas,
			      get_entry_by_index, get_n_entries,
			      entry->cm_root_cert_store_files,
			      entry->cm_root_cert_store_nssdbs);
	hooks = collect_hooks(context, hooks, cm_hook_pre_save,
			      get_ca_by_index, get_n_cas,
			      get_entry_by_index, get_n_entries,
			      entry->cm_other_root_cert_store_files,
			      entry->cm_other_root_cert_store_nssdbs);
	hooks = collect_hooks(context, hooks, cm_hook_pre_save,
			      get_ca_by_index, get_n_cas,
			      get_entry_by_index, get_n_entries,
			      entry->cm_other_cert_store_files,
			      entry->cm_other_cert_store_nssdbs);
	/* Add the entry's own presave hook. */
	hooks = add_hook(hooks, entry->cm_pre_certsave_command,
		         entry->cm_pre_certsave_uid);
	return cm_hook_start(NULL, entry, context, "pre-save", hooks);
}

/* Start the post-save hook. */
struct cm_hook_state *
cm_hook_start_postsave(struct cm_store_entry *entry,
		       struct cm_context *context,
		       struct cm_store_ca *(*get_ca_by_index)(struct cm_context *, int),
		       int (*get_n_cas)(struct cm_context *),
		       struct cm_store_entry *(*get_entry_by_index)(struct cm_context *, int),
		       int (*get_n_entries)(struct cm_context *))
{
	struct cm_hook_list *hooks = NULL;

	/* Make a list of the postsave hooks from all of the entries and CAs
	 * which reference the storage locations for the certificates that are
	 * referenced by this entry. */
	hooks = collect_hooks(context, hooks, cm_hook_post_save,
			      get_ca_by_index, get_n_cas,
			      get_entry_by_index, get_n_entries,
			      entry->cm_root_cert_store_files,
			      entry->cm_root_cert_store_nssdbs);
	hooks = collect_hooks(context, hooks, cm_hook_post_save,
			      get_ca_by_index, get_n_cas,
			      get_entry_by_index, get_n_entries,
			      entry->cm_other_root_cert_store_files,
			      entry->cm_other_root_cert_store_nssdbs);
	hooks = collect_hooks(context, hooks, cm_hook_post_save,
			      get_ca_by_index, get_n_cas,
			      get_entry_by_index, get_n_entries,
			      entry->cm_other_cert_store_files,
			      entry->cm_other_cert_store_nssdbs);
	/* Add the entry's own postsave hook. */
	hooks = add_hook(hooks, entry->cm_post_certsave_command,
		         entry->cm_post_certsave_uid);
	return cm_hook_start(NULL, entry, context, "post-save", hooks);
}

/* Start the CA pre-save hook. */
struct cm_hook_state *
cm_hook_start_ca_presave(struct cm_store_ca *ca,
			 struct cm_context *context,
			 struct cm_store_ca *(*get_ca_by_index)(struct cm_context *, int),
			 int (*get_n_cas)(struct cm_context *),
			 struct cm_store_entry *(*get_entry_by_index)(struct cm_context *, int),
			 int (*get_n_entries)(struct cm_context *))
{
	struct cm_hook_list *hooks = NULL;

	/* Make a list of the presave hooks from all of the entries and CAs
	 * which reference the storage locations for the certificates that are
	 * referenced by this CA. */
	hooks = collect_hooks(context, hooks, cm_hook_ca_pre_save,
			      get_ca_by_index, get_n_cas,
			      get_entry_by_index, get_n_entries,
			      ca->cm_ca_root_cert_store_files,
			      ca->cm_ca_root_cert_store_nssdbs);
	hooks = collect_hooks(context, hooks, cm_hook_ca_pre_save,
			      get_ca_by_index, get_n_cas,
			      get_entry_by_index, get_n_entries,
			      ca->cm_ca_other_root_cert_store_files,
			      ca->cm_ca_other_root_cert_store_nssdbs);
	hooks = collect_hooks(context, hooks, cm_hook_ca_pre_save,
			      get_ca_by_index, get_n_cas,
			      get_entry_by_index, get_n_entries,
			      ca->cm_ca_other_cert_store_files,
			      ca->cm_ca_other_cert_store_nssdbs);
	return cm_hook_start(ca, NULL, context, "ca-pre-save", hooks);
}

/* Start the CA post-save hook. */
struct cm_hook_state *
cm_hook_start_ca_postsave(struct cm_store_ca *ca,
			  struct cm_context *context,
			  struct cm_store_ca *(*get_ca_by_index)(struct cm_context *, int),
			  int (*get_n_cas)(struct cm_context *),
			  struct cm_store_entry *(*get_entry_by_index)(struct cm_context *, int),
			  int (*get_n_entries)(struct cm_context *))
{
	struct cm_hook_list *hooks = NULL;

	/* Make a list of the postsave hooks from all of the entries and CAs
	 * which reference the storage locations for the certificates that are
	 * referenced by this CA. */
	hooks = collect_hooks(context, hooks, cm_hook_ca_post_save,
			      get_ca_by_index, get_n_cas,
			      get_entry_by_index, get_n_entries,
			      ca->cm_ca_root_cert_store_files,
			      ca->cm_ca_root_cert_store_nssdbs);
	hooks = collect_hooks(context, hooks, cm_hook_ca_post_save,
			      get_ca_by_index, get_n_cas,
			      get_entry_by_index, get_n_entries,
			      ca->cm_ca_other_root_cert_store_files,
			      ca->cm_ca_other_root_cert_store_nssdbs);
	hooks = collect_hooks(context, hooks, cm_hook_ca_post_save,
			      get_ca_by_index, get_n_cas,
			      get_entry_by_index, get_n_entries,
			      ca->cm_ca_other_cert_store_files,
			      ca->cm_ca_other_cert_store_nssdbs);
	return cm_hook_start(ca, NULL, context, "ca-post-save", hooks);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
int
cm_hook_get_fd(struct cm_hook_state *state)
{
	if (state->subproc != NULL) {
		return cm_subproc_get_fd(state->subproc);
	}
	return -1;
}

/* Check if our child process has exited. */
int
cm_hook_ready(struct cm_hook_state *state)
{
	int result = -1;

	if (state->subproc != NULL) {
		result = cm_subproc_ready(state->subproc);
	}
	if (result == 0) {
		if (state->hooks->next != NULL) {
			/* Clean up this subprocess. */
			if (state->subproc != NULL) {
				cm_subproc_done(state->subproc);
			}
			/* Start the next subprocess. */
			state->hooks = state->hooks->next;
			state->subproc = cm_subproc_start(cm_hook_main, state,
							  state->ca,
							  state->entry, state);
			if (state->subproc == NULL) {
				cm_log(0, "Error starting command \"%s\".\n",
				       state->hooks->command);
			} else {
				/* "Try again", though the caller will actually
				 * be waiting on the new subprocess. */
				return -1;
			}
		}
	}
	return result;
}

/* Clean up after... well, we don't really know. */
void
cm_hook_done(struct cm_hook_state *state)
{
	if (state->subproc != NULL) {
		cm_subproc_done(state->subproc);
	}
	talloc_free(state);
}
