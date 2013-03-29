/*
   Copyright (c) 2013 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/
#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif
#include <inttypes.h>


#include "globals.h"
#include "glusterfs.h"
#include "compat.h"
#include "dict.h"
#include "protocol-common.h"
#include "xlator.h"
#include "logging.h"
#include "timer.h"
#include "compat.h"
#include "compat-errno.h"
#include "statedump.h"
#include "run.h"
#include "glusterd-mem-types.h"
#include "glusterd.h"
#include "glusterd-op-sm.h"
#include "glusterd-sm.h"
#include "glusterd-utils.h"
#include "glusterd-store.h"

#include "glusterd1-xdr.h"
#include "cli1-xdr.h"
#include "xdr-generic.h"
#include "rpc-clnt.h"
#include "glusterd-volgen.h"
#include "glusterd-mountbroker.h"

#include <sys/resource.h>
#include <inttypes.h>

#include "common-utils.h"

#include "globals.h"
#include "glusterd-syncop.h"

#ifdef HAVE_BD_XLATOR
#include <lvm2app.h>
#endif


static int
glusterd_handle_friend_req (rpcsvc_request_t *req, uuid_t  uuid,
                            char *hostname, int port,
                            gd1_mgmt_friend_req *friend_req)
{
        int                             ret = -1;
        glusterd_peerinfo_t             *peerinfo = NULL;
        glusterd_friend_sm_event_t      *event = NULL;
        glusterd_friend_req_ctx_t       *ctx = NULL;
        char                            rhost[UNIX_PATH_MAX + 1] = {0};
        uuid_t                          friend_uuid = {0};
        dict_t                          *dict = NULL;

        uuid_parse (uuid_utoa (uuid), friend_uuid);
        if (!port)
                port = GF_DEFAULT_BASE_PORT;

        ret = glusterd_remote_hostname_get (req, rhost, sizeof (rhost));
        ret = glusterd_friend_find (uuid, rhost, &peerinfo);

        if (ret) {
                ret = glusterd_xfer_friend_add_resp (req, rhost, port, -1,
                                                     GF_PROBE_UNKNOWN_PEER);
                if (friend_req->vols.vols_val) {
                        free (friend_req->vols.vols_val);
                        friend_req->vols.vols_val = NULL;
                }
                goto out;
        }

        ret = glusterd_friend_sm_new_event
                        (GD_FRIEND_EVENT_RCVD_FRIEND_REQ, &event);

        if (ret) {
                gf_log ("", GF_LOG_ERROR, "event generation failed: %d", ret);
                return ret;
        }

        event->peerinfo = peerinfo;

        ctx = GF_CALLOC (1, sizeof (*ctx), gf_gld_mt_friend_req_ctx_t);

        if (!ctx) {
                gf_log ("", GF_LOG_ERROR, "Unable to allocate memory");
                ret = -1;
                goto out;
        }

        uuid_copy (ctx->uuid, uuid);
        if (hostname)
                ctx->hostname = gf_strdup (hostname);
        ctx->req = req;

        dict = dict_new ();
        if (!dict) {
                ret = -1;
                goto out;
        }

        ret = dict_unserialize (friend_req->vols.vols_val,
                                friend_req->vols.vols_len,
                                &dict);

        if (ret)
                goto out;
        else
                dict->extra_stdfree = friend_req->vols.vols_val;

        ctx->vols = dict;
        event->ctx = ctx;

        ret = glusterd_friend_sm_inject_event (event);
        if (ret) {
                gf_log ("glusterd", GF_LOG_ERROR, "Unable to inject event %d, "
                        "ret = %d", event->event, ret);
                goto out;
        }

        ret = 0;

out:
        if (0 != ret) {
                if (ctx && ctx->hostname)
                        GF_FREE (ctx->hostname);
                GF_FREE (ctx);
                if (dict) {
                        if ((!dict->extra_stdfree) &&
                            friend_req->vols.vols_val)
                                free (friend_req->vols.vols_val);
                        dict_unref (dict);
                } else {
                    free (friend_req->vols.vols_val);
                }
                GF_FREE (event);
        } else {
                if (peerinfo && (0 == peerinfo->connected))
                        ret = GLUSTERD_CONNECTION_AWAITED;
        }
        return ret;
}


static int
glusterd_handle_unfriend_req (rpcsvc_request_t *req, uuid_t  uuid,
                              char *hostname, int port)
{
        int                             ret = -1;
        glusterd_peerinfo_t             *peerinfo = NULL;
        glusterd_friend_sm_event_t      *event = NULL;
        glusterd_friend_req_ctx_t       *ctx = NULL;

        if (!port)
                port = GF_DEFAULT_BASE_PORT;

        ret = glusterd_friend_find (uuid, hostname, &peerinfo);

        if (ret) {
                gf_log ("glusterd", GF_LOG_CRITICAL,
                        "Received remove-friend from unknown peer %s",
                        hostname);
                ret = glusterd_xfer_friend_remove_resp (req, hostname,
                                                        port);
                goto out;
        }

        ret = glusterd_friend_sm_new_event
                        (GD_FRIEND_EVENT_RCVD_REMOVE_FRIEND, &event);

        if (ret) {
                gf_log ("", GF_LOG_ERROR, "event generation failed: %d", ret);
                return ret;
        }

        event->peerinfo = peerinfo;

        ctx = GF_CALLOC (1, sizeof (*ctx), gf_gld_mt_friend_req_ctx_t);

        if (!ctx) {
                gf_log ("", GF_LOG_ERROR, "Unable to allocate memory");
                ret = -1;
                goto out;
        }

        uuid_copy (ctx->uuid, uuid);
        if (hostname)
                ctx->hostname = gf_strdup (hostname);
        ctx->req = req;

        event->ctx = ctx;

        ret = glusterd_friend_sm_inject_event (event);

        if (ret) {
                gf_log ("glusterd", GF_LOG_ERROR, "Unable to inject event %d, "
                        "ret = %d", event->event, ret);
                goto out;
        }

        ret = 0;

out:
        if (0 != ret) {
                if (ctx && ctx->hostname)
                        GF_FREE (ctx->hostname);
                GF_FREE (ctx);
        }

        return ret;
}

static int
glusterd_add_peer_detail_to_dict (glusterd_peerinfo_t   *peerinfo,
                                  dict_t  *friends, int   count)
{

        int             ret = -1;
        char            key[256] = {0, };

        GF_ASSERT (peerinfo);
        GF_ASSERT (friends);

        snprintf (key, 256, "friend%d.uuid", count);
        uuid_utoa_r (peerinfo->uuid, peerinfo->uuid_str);
        ret = dict_set_str (friends, key, peerinfo->uuid_str);
        if (ret)
                goto out;

        snprintf (key, 256, "friend%d.hostname", count);
        ret = dict_set_str (friends, key, peerinfo->hostname);
        if (ret)
                goto out;

        snprintf (key, 256, "friend%d.port", count);
        ret = dict_set_int32 (friends, key, peerinfo->port);
        if (ret)
                goto out;

        snprintf (key, 256, "friend%d.stateId", count);
        ret = dict_set_int32 (friends, key, peerinfo->state.state);
        if (ret)
                goto out;

        snprintf (key, 256, "friend%d.state", count);
        ret = dict_set_str (friends, key,
                    glusterd_friend_sm_state_name_get(peerinfo->state.state));
        if (ret)
                goto out;

        snprintf (key, 256, "friend%d.connected", count);
        ret = dict_set_int32 (friends, key, (int32_t)peerinfo->connected);
        if (ret)
                goto out;

out:
        return ret;
}


int
glusterd_friend_find (uuid_t uuid, char *hostname,
                      glusterd_peerinfo_t **peerinfo)
{
        int     ret = -1;
        xlator_t *this = NULL;

        this = THIS;
        GF_ASSERT (this);

        if (uuid) {
                ret = glusterd_friend_find_by_uuid (uuid, peerinfo);

                if (ret) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                 "Unable to find peer by uuid: %s",
                                 uuid_utoa (uuid));
                } else {
                        goto out;
                }

        }

        if (hostname) {
                ret = glusterd_friend_find_by_hostname (hostname, peerinfo);

                if (ret) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "Unable to find hostname: %s", hostname);
                } else {
                        goto out;
                }
        }

out:
        return ret;
}


int
glusterd_handle_incoming_friend_req (rpcsvc_request_t *req)
{
        int32_t                 ret = -1;
        gd1_mgmt_friend_req     friend_req = {{0},};
        gf_boolean_t            run_fsm = _gf_true;

        GF_ASSERT (req);
        ret = xdr_to_generic (req->msg[0], &friend_req,
                              (xdrproc_t)xdr_gd1_mgmt_friend_req);
        if (ret < 0) {
                //failed to decode msg;
                req->rpc_err = GARBAGE_ARGS;
                goto out;
        }

        gf_log ("glusterd", GF_LOG_INFO,
                "Received probe from uuid: %s", uuid_utoa (friend_req.uuid));
        ret = glusterd_handle_friend_req (req, friend_req.uuid,
                                          friend_req.hostname, friend_req.port,
                                          &friend_req);

        if (ret == GLUSTERD_CONNECTION_AWAITED) {
                //fsm should be run after connection establishes
                run_fsm = _gf_false;
                ret = 0;
        }

out:
        free (friend_req.hostname);//malloced by xdr

        if (run_fsm) {
                glusterd_friend_sm ();
                glusterd_op_sm ();
        }

        return ret;
}


int
glusterd_handle_incoming_unfriend_req (rpcsvc_request_t *req)
{
        int32_t                 ret = -1;
        gd1_mgmt_friend_req     friend_req = {{0},};
        char               remote_hostname[UNIX_PATH_MAX + 1] = {0,};

        GF_ASSERT (req);
        ret = xdr_to_generic (req->msg[0], &friend_req,
                              (xdrproc_t)xdr_gd1_mgmt_friend_req);
        if (ret < 0) {
                //failed to decode msg;
                req->rpc_err = GARBAGE_ARGS;
                goto out;
        }

        gf_log ("glusterd", GF_LOG_INFO,
                "Received unfriend from uuid: %s", uuid_utoa (friend_req.uuid));

        ret = glusterd_remote_hostname_get (req, remote_hostname,
                                            sizeof (remote_hostname));
        if (ret) {
                gf_log ("", GF_LOG_ERROR, "Unable to get the remote hostname");
                goto out;
        }
        ret = glusterd_handle_unfriend_req (req, friend_req.uuid,
                                            remote_hostname, friend_req.port);

out:
        free (friend_req.hostname);//malloced by xdr
        free (friend_req.vols.vols_val);//malloced by xdr

        glusterd_friend_sm ();
        glusterd_op_sm ();

        return ret;
}


int
glusterd_handle_friend_update_delete (dict_t *dict)
{
        char                    *hostname = NULL;
        int32_t                 ret = -1;

        GF_ASSERT (dict);

        ret = dict_get_str (dict, "hostname", &hostname);
        if (ret)
                goto out;

        ret = glusterd_friend_remove (NULL, hostname);

out:
        gf_log ("", GF_LOG_DEBUG, "Returning %d", ret);
        return ret;
}


int
glusterd_friend_hostname_update (glusterd_peerinfo_t *peerinfo,
                                char *hostname,
                                gf_boolean_t store_update)
{
        char                    *new_hostname = NULL;
        int                     ret = 0;

        GF_ASSERT (peerinfo);
        GF_ASSERT (hostname);

        new_hostname = gf_strdup (hostname);
        if (!new_hostname) {
                ret = -1;
                goto out;
        }

        GF_FREE (peerinfo->hostname);
        peerinfo->hostname = new_hostname;
        if (store_update)
                ret = glusterd_store_peerinfo (peerinfo);
out:
        gf_log ("", GF_LOG_DEBUG, "Returning %d", ret);
        return ret;
}


int
glusterd_handle_friend_update (rpcsvc_request_t *req)
{
        int32_t                 ret = -1;
        gd1_mgmt_friend_update     friend_req = {{0},};
        glusterd_peerinfo_t     *peerinfo = NULL;
        glusterd_conf_t         *priv = NULL;
        xlator_t                *this = NULL;
        glusterd_peerinfo_t     *tmp = NULL;
        gd1_mgmt_friend_update_rsp rsp = {{0},};
        dict_t                  *dict = NULL;
        char                    key[100] = {0,};
        char                    *uuid_buf = NULL;
        char                    *hostname = NULL;
        int                     i = 1;
        int                     count = 0;
        uuid_t                  uuid = {0,};
        glusterd_peerctx_args_t args = {0};
        int32_t                 op = 0;

        GF_ASSERT (req);

        this = THIS;
        GF_ASSERT (this);
        priv = this->private;
        GF_ASSERT (priv);

        ret = xdr_to_generic (req->msg[0], &friend_req,
                              (xdrproc_t)xdr_gd1_mgmt_friend_update);
        if (ret < 0) {
                //failed to decode msg;
                req->rpc_err = GARBAGE_ARGS;
                goto out;
        }

        ret = glusterd_friend_find (friend_req.uuid, NULL, &tmp);
        if (ret) {
                gf_log ("", GF_LOG_CRITICAL, "Received friend update request "
                        "from unknown peer %s", uuid_utoa (friend_req.uuid));
                goto out;
        }
        gf_log ("glusterd", GF_LOG_INFO,
                "Received friend update from uuid: %s", uuid_utoa (friend_req.uuid));

        if (friend_req.friends.friends_len) {
                /* Unserialize the dictionary */
                dict  = dict_new ();

                ret = dict_unserialize (friend_req.friends.friends_val,
                                        friend_req.friends.friends_len,
                                        &dict);
                if (ret < 0) {
                        gf_log ("glusterd", GF_LOG_ERROR,
                                "failed to "
                                "unserialize req-buffer to dictionary");
                        goto out;
                } else {
                        dict->extra_stdfree = friend_req.friends.friends_val;
                }
        }

        ret = dict_get_int32 (dict, "count", &count);
        if (ret)
                goto out;

        ret = dict_get_int32 (dict, "op", &op);
        if (ret)
                goto out;

        if (GD_FRIEND_UPDATE_DEL == op) {
                ret = glusterd_handle_friend_update_delete (dict);
                goto out;
        }

        args.mode = GD_MODE_ON;
        while ( i <= count) {
                snprintf (key, sizeof (key), "friend%d.uuid", i);
                ret = dict_get_str (dict, key, &uuid_buf);
                if (ret)
                        goto out;
                uuid_parse (uuid_buf, uuid);
                snprintf (key, sizeof (key), "friend%d.hostname", i);
                ret = dict_get_str (dict, key, &hostname);
                if (ret)
                        goto out;

                gf_log ("", GF_LOG_INFO, "Received uuid: %s, hostname:%s",
                                uuid_buf, hostname);

                if (uuid_is_null (uuid)) {
                        gf_log (this->name, GF_LOG_WARNING, "Updates mustn't "
                                "contain peer with 'null' uuid");
                        continue;
                }

                if (!uuid_compare (uuid, MY_UUID)) {
                        gf_log ("", GF_LOG_INFO, "Received my uuid as Friend");
                        i++;
                        continue;
                }

                ret = glusterd_friend_find (uuid, hostname, &tmp);

                if (!ret) {
                        if (strcmp (hostname, tmp->hostname) != 0) {
                                glusterd_friend_hostname_update (tmp, hostname,
                                                                 _gf_true);
                        }
                        i++;
                        continue;
                }

                ret = glusterd_friend_add (hostname, friend_req.port,
                                           GD_FRIEND_STATE_BEFRIENDED,
                                           &uuid, &peerinfo, 0, &args);

                i++;
        }

out:
        uuid_copy (rsp.uuid, MY_UUID);
        ret = glusterd_submit_reply (req, &rsp, NULL, 0, NULL,
                                     (xdrproc_t)xdr_gd1_mgmt_friend_update_rsp);
        if (dict) {
                if (!dict->extra_stdfree && friend_req.friends.friends_val)
                        free (friend_req.friends.friends_val);//malloced by xdr
                dict_unref (dict);
        } else {
                free (friend_req.friends.friends_val);//malloced by xdr
        }

        glusterd_friend_sm ();
        glusterd_op_sm ();

        return ret;
}


int
glusterd_handle_probe_query (rpcsvc_request_t *req)
{
        int32_t                         ret = -1;
        xlator_t                        *this = NULL;
        glusterd_conf_t                 *conf = NULL;
        gd1_mgmt_probe_req              probe_req = {{0},};
        gd1_mgmt_probe_rsp              rsp = {{0},};
        glusterd_peerinfo_t             *peerinfo = NULL;
        glusterd_peerctx_args_t         args = {0};
        int                             port = 0;
        char               remote_hostname[UNIX_PATH_MAX + 1] = {0,};

        GF_ASSERT (req);

        ret = xdr_to_generic (req->msg[0], &probe_req,
                              (xdrproc_t)xdr_gd1_mgmt_probe_req);
        if (ret < 0) {
                //failed to decode msg;
                req->rpc_err = GARBAGE_ARGS;
                goto out;
        }

        this = THIS;

        conf = this->private;
        if (probe_req.port)
                port = probe_req.port;
        else
                port = GF_DEFAULT_BASE_PORT;

        gf_log ("glusterd", GF_LOG_INFO,
                "Received probe from uuid: %s", uuid_utoa (probe_req.uuid));

        /* Check for uuid collision and handle it in a user friendly way by
         * sending the error.
         */
        if (!uuid_compare (probe_req.uuid, MY_UUID)) {
                gf_log (THIS->name, GF_LOG_ERROR, "Peer uuid %s is same as "
                        "local uuid. Please check the uuid of both the peers "
                        "from %s/%s", uuid_utoa (probe_req.uuid),
                        GLUSTERD_DEFAULT_WORKDIR, GLUSTERD_INFO_FILE);
                rsp.op_ret = -1;
                rsp.op_errno = GF_PROBE_SAME_UUID;
                rsp.port = port;
                goto respond;
        }

        ret = glusterd_remote_hostname_get (req, remote_hostname,
                                            sizeof (remote_hostname));
        if (ret) {
                gf_log ("", GF_LOG_ERROR, "Unable to get the remote hostname");
                goto out;
        }
        ret = glusterd_friend_find (probe_req.uuid, remote_hostname, &peerinfo);
        if ((ret != 0 ) && (!list_empty (&conf->peers))) {
                rsp.op_ret = -1;
                rsp.op_errno = GF_PROBE_ANOTHER_CLUSTER;
        } else if (ret) {
                gf_log ("glusterd", GF_LOG_INFO, "Unable to find peerinfo"
                        " for host: %s (%d)", remote_hostname, port);
                args.mode = GD_MODE_ON;
                ret = glusterd_friend_add (remote_hostname, port,
                                           GD_FRIEND_STATE_PROBE_RCVD,
                                           NULL, &peerinfo, 0, &args);
                if (ret) {
                        gf_log ("", GF_LOG_ERROR, "Failed to add peer %s",
                                remote_hostname);
                        rsp.op_errno = GF_PROBE_ADD_FAILED;
                }
        }

respond:
        uuid_copy (rsp.uuid, MY_UUID);

        rsp.hostname = probe_req.hostname;
        rsp.op_errstr = "";

        glusterd_submit_reply (req, &rsp, NULL, 0, NULL,
                               (xdrproc_t)xdr_gd1_mgmt_probe_rsp);
        ret = 0;

        gf_log ("glusterd", GF_LOG_INFO, "Responded to %s, op_ret: %d, "
                "op_errno: %d, ret: %d", remote_hostname,
                rsp.op_ret, rsp.op_errno, ret);

out:
        free (probe_req.hostname);//malloced by xdr

        glusterd_friend_sm ();
        glusterd_op_sm ();

        return ret;
}


int
glusterd_friend_remove (uuid_t uuid, char *hostname)
{
        int                           ret = 0;
        glusterd_peerinfo_t           *peerinfo = NULL;

        ret = glusterd_friend_find (uuid, hostname, &peerinfo);
        if (ret)
                goto out;

        ret = glusterd_friend_remove_cleanup_vols (peerinfo->uuid);
        if (ret)
                gf_log (THIS->name, GF_LOG_WARNING, "Volumes cleanup failed");
        ret = glusterd_friend_cleanup (peerinfo);
out:
        gf_log ("", GF_LOG_DEBUG, "returning %d", ret);
        return ret;
}


int
glusterd_rpc_create (struct rpc_clnt **rpc,
                     dict_t *options,
                     rpc_clnt_notify_t notify_fn,
                     void *notify_data)
{
        struct rpc_clnt         *new_rpc = NULL;
        int                     ret = -1;
        xlator_t                *this = NULL;

        this = THIS;
        GF_ASSERT (this);

        GF_ASSERT (options);

        /* TODO: is 32 enough? or more ? */
        new_rpc = rpc_clnt_new (options, this->ctx, this->name, 16);
        if (!new_rpc)
                goto out;

        ret = rpc_clnt_register_notify (new_rpc, notify_fn, notify_data);
        *rpc = new_rpc;
        if (ret)
                goto out;
        ret = rpc_clnt_start (new_rpc);
out:
        if (ret) {
                if (new_rpc) {
                        (void) rpc_clnt_unref (new_rpc);
                }
        }

        gf_log (this->name, GF_LOG_DEBUG, "returning %d", ret);
        return ret;
}


int
glusterd_transport_keepalive_options_get (int *interval, int *time)
{
        int     ret = 0;
        xlator_t *this = NULL;

        this = THIS;
        GF_ASSERT (this);

        ret = dict_get_int32 (this->options,
                              "transport.socket.keepalive-interval",
                              interval);
        ret = dict_get_int32 (this->options,
                              "transport.socket.keepalive-time",
                              time);
        return 0;
}


int
glusterd_transport_inet_options_build (dict_t **options, const char *hostname,
                                       int port)
{
        dict_t  *dict = NULL;
        int32_t interval = -1;
        int32_t time     = -1;
        int     ret = 0;

        GF_ASSERT (options);
        GF_ASSERT (hostname);

        if (!port)
                port = GLUSTERD_DEFAULT_PORT;

        /* Build default transport options */
        ret = rpc_transport_inet_options_build (&dict, hostname, port);
        if (ret)
                goto out;

        /* Set frame-timeout to 10mins. Default timeout of 30 mins is too long
         * when compared to 2 mins for cli timeout. This ensures users don't
         * wait too long after cli timesout before being able to resume normal
         * operations
         */
        ret = dict_set_int32 (dict, "frame-timeout", 600);
        if (ret) {
                gf_log ("glusterd", GF_LOG_ERROR,
                        "Failed to set frame-timeout");
                goto out;
        }

        /* Set keepalive options */
        glusterd_transport_keepalive_options_get (&interval, &time);

        if ((interval > 0) || (time > 0))
                ret = rpc_transport_keepalive_options_set (dict, interval, time);
        *options = dict;
out:
        gf_log ("glusterd", GF_LOG_DEBUG, "Returning %d", ret);
        return ret;
}


int
glusterd_friend_rpc_create (xlator_t *this, glusterd_peerinfo_t *peerinfo,
                            glusterd_peerctx_args_t *args)
{
        dict_t                 *options = NULL;
        int                    ret = -1;
        glusterd_peerctx_t     *peerctx = NULL;
        data_t                 *data = NULL;

        peerctx = GF_CALLOC (1, sizeof (*peerctx), gf_gld_mt_peerctx_t);
        if (!peerctx)
                goto out;

        if (args)
                peerctx->args = *args;

        peerctx->peerinfo = peerinfo;

        ret = glusterd_transport_inet_options_build (&options,
                                                     peerinfo->hostname,
                                                     peerinfo->port);
        if (ret)
                goto out;

        /*
         * For simulated multi-node testing, we need to make sure that we
         * create our RPC endpoint with the same address that the peer would
         * use to reach us.
         */
        if (this->options) {
                data = dict_get(this->options,"transport.socket.bind-address");
                if (data) {
                        ret = dict_set(options,
                                       "transport.socket.source-addr",data);
                }
        }

        ret = glusterd_rpc_create (&peerinfo->rpc, options,
                                   glusterd_peer_rpc_notify, peerctx);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "failed to create rpc for"
                        " peer %s", peerinfo->hostname);
                goto out;
        }
        peerctx = NULL;
        ret = 0;
out:
        GF_FREE (peerctx);
        return ret;
}


int
glusterd_friend_add (const char *hoststr, int port,
                     glusterd_friend_sm_state_t state,
                     uuid_t *uuid,
                     glusterd_peerinfo_t **friend,
                     gf_boolean_t restore,
                     glusterd_peerctx_args_t *args)
{
        int                     ret = 0;
        xlator_t               *this = NULL;
        glusterd_conf_t        *conf = NULL;

        this = THIS;
        conf = this->private;
        GF_ASSERT (conf);
        GF_ASSERT (hoststr);

        ret = glusterd_peerinfo_new (friend, state, uuid, hoststr, port);
        if (ret) {
                goto out;
        }

        /*
         * We can't add to the list after calling glusterd_friend_rpc_create,
         * even if it succeeds, because by then the callback to take it back
         * off and free might have happened already (notably in the case of an
         * invalid peer name).  That would mean we're adding something that had
         * just been free, and we're likely to crash later.
         */
        list_add_tail (&(*friend)->uuid_list, &conf->peers);

        //restore needs to first create the list of peers, then create rpcs
        //to keep track of quorum in race-free manner. In restore for each peer
        //rpc-create calls rpc_notify when the friend-list is partially
        //constructed, leading to wrong quorum calculations.
        if (!restore) {
                ret = glusterd_store_peerinfo (*friend);
                if (ret == 0) {
                        ret = glusterd_friend_rpc_create (this, *friend, args);
                }
                else {
                        gf_log (this->name, GF_LOG_ERROR,
                                "Failed to store peerinfo");
                }
        }

        if (ret) {
                (void) glusterd_friend_cleanup (*friend);
                *friend = NULL;
        }

out:
        gf_log (this->name, GF_LOG_INFO, "connect returned %d", ret);
        return ret;
}


int
glusterd_probe_begin (rpcsvc_request_t *req, const char *hoststr, int port)
{
        int                             ret = -1;
        glusterd_peerinfo_t             *peerinfo = NULL;
        glusterd_peerctx_args_t         args = {0};
        glusterd_friend_sm_event_t      *event = NULL;

        GF_ASSERT (hoststr);

        ret = glusterd_friend_find (NULL, (char *)hoststr, &peerinfo);

        if (ret) {
                gf_log ("glusterd", GF_LOG_INFO, "Unable to find peerinfo"
                        " for host: %s (%d)", hoststr, port);
                args.mode = GD_MODE_ON;
                args.req  = req;
                ret = glusterd_friend_add ((char *)hoststr, port,
                                           GD_FRIEND_STATE_DEFAULT,
                                           NULL, &peerinfo, 0, &args);
                if ((!ret) && (!peerinfo->connected)) {
                        ret = GLUSTERD_CONNECTION_AWAITED;
                }

        } else if (peerinfo->connected &&
                   (GD_FRIEND_STATE_BEFRIENDED == peerinfo->state.state)) {
                ret = glusterd_friend_hostname_update (peerinfo, (char*)hoststr,
                                                       _gf_false);
                if (ret)
                        goto out;
                //this is just to rename so inject local acc for cluster update
                ret = glusterd_friend_sm_new_event (GD_FRIEND_EVENT_LOCAL_ACC,
                                                    &event);
                if (!ret) {
                        event->peerinfo = peerinfo;
                        ret = glusterd_friend_sm_inject_event (event);
                        glusterd_xfer_cli_probe_resp (req, 0, GF_PROBE_SUCCESS,
                                                      NULL, (char*)hoststr,
                                                      port);
                }
        } else {
                glusterd_xfer_cli_probe_resp (req, 0, GF_PROBE_FRIEND, NULL,
                                              (char*)hoststr, port);
        }

out:
        gf_log ("", GF_LOG_DEBUG, "returning %d", ret);
        return ret;
}


int
glusterd_deprobe_begin (rpcsvc_request_t *req, const char *hoststr, int port,
                        uuid_t uuid)
{
        int                             ret = -1;
        glusterd_peerinfo_t             *peerinfo = NULL;
        glusterd_friend_sm_event_t      *event = NULL;
        glusterd_probe_ctx_t            *ctx = NULL;

        GF_ASSERT (hoststr);
        GF_ASSERT (req);

        ret = glusterd_friend_find (uuid, (char *)hoststr, &peerinfo);

        if (ret) {
                gf_log ("glusterd", GF_LOG_INFO, "Unable to find peerinfo"
                        " for host: %s %d", hoststr, port);
                goto out;
        }

        if (!peerinfo->rpc) {
                //handle this case
                goto out;
        }

        ret = glusterd_friend_sm_new_event
                (GD_FRIEND_EVENT_INIT_REMOVE_FRIEND, &event);

        if (ret) {
                gf_log ("glusterd", GF_LOG_ERROR,
                                "Unable to get new event");
                return ret;
        }

        ctx = GF_CALLOC (1, sizeof(*ctx), gf_gld_mt_probe_ctx_t);

        if (!ctx) {
                goto out;
        }

        ctx->hostname = gf_strdup (hoststr);
        ctx->port = port;
        ctx->req = req;

        event->ctx = ctx;

        event->peerinfo = peerinfo;

        ret = glusterd_friend_sm_inject_event (event);

        if (ret) {
                gf_log ("glusterd", GF_LOG_ERROR, "Unable to inject event %d, "
                        "ret = %d", event->event, ret);
                goto out;
        }

out:
        return ret;
}


int
glusterd_xfer_friend_remove_resp (rpcsvc_request_t *req, char *hostname, int port)
{
        gd1_mgmt_friend_rsp  rsp = {{0}, };
        int32_t              ret = -1;
        xlator_t             *this = NULL;
        glusterd_conf_t      *conf = NULL;

        GF_ASSERT (hostname);

        rsp.op_ret = 0;
        this = THIS;
        GF_ASSERT (this);

        conf = this->private;

        uuid_copy (rsp.uuid, MY_UUID);
        rsp.hostname = hostname;
        rsp.port = port;
        ret = glusterd_submit_reply (req, &rsp, NULL, 0, NULL,
                                     (xdrproc_t)xdr_gd1_mgmt_friend_rsp);

        gf_log ("glusterd", GF_LOG_INFO,
                "Responded to %s (%d), ret: %d", hostname, port, ret);
        return ret;
}


int
glusterd_xfer_friend_add_resp (rpcsvc_request_t *req, char *hostname, int port,
                               int32_t op_ret, int32_t op_errno)
{
        gd1_mgmt_friend_rsp  rsp = {{0}, };
        int32_t              ret = -1;
        xlator_t             *this = NULL;
        glusterd_conf_t      *conf = NULL;

        GF_ASSERT (hostname);

        this = THIS;
        GF_ASSERT (this);

        conf = this->private;

        uuid_copy (rsp.uuid, MY_UUID);
        rsp.op_ret = op_ret;
        rsp.op_errno = op_errno;
        rsp.hostname = gf_strdup (hostname);
        rsp.port = port;

        ret = glusterd_submit_reply (req, &rsp, NULL, 0, NULL,
                                     (xdrproc_t)xdr_gd1_mgmt_friend_rsp);

        gf_log ("glusterd", GF_LOG_INFO,
                "Responded to %s (%d), ret: %d", hostname, port, ret);
        GF_FREE (rsp.hostname);
        return ret;
}


int
glusterd_xfer_cli_probe_resp (rpcsvc_request_t *req, int32_t op_ret,
                              int32_t op_errno, char *op_errstr, char *hostname,
                              int port)
{
        gf1_cli_probe_rsp    rsp = {0, };
        int32_t              ret = -1;

        GF_ASSERT (req);

        rsp.op_ret = op_ret;
        rsp.op_errno = op_errno;
        rsp.op_errstr = op_errstr ? op_errstr : "";
        rsp.hostname = hostname;
        rsp.port = port;

        ret = glusterd_submit_reply (req, &rsp, NULL, 0, NULL,
                                     (xdrproc_t)xdr_gf1_cli_probe_rsp);

        gf_log ("glusterd", GF_LOG_INFO, "Responded to CLI, ret: %d",ret);

        return ret;
}


int
glusterd_xfer_cli_deprobe_resp (rpcsvc_request_t *req, int32_t op_ret,
                                int32_t op_errno, char *op_errstr,
                                char *hostname)
{
        gf1_cli_deprobe_rsp    rsp = {0, };
        int32_t                ret = -1;

        GF_ASSERT (req);

        rsp.op_ret = op_ret;
        rsp.op_errno = op_errno;
        rsp.op_errstr = op_errstr ? op_errstr : "";
        rsp.hostname = hostname;

        ret = glusterd_submit_reply (req, &rsp, NULL, 0, NULL,
                                     (xdrproc_t)xdr_gf1_cli_deprobe_rsp);

        gf_log ("glusterd", GF_LOG_INFO, "Responded to CLI, ret: %d",ret);

        return ret;
}


int32_t
glusterd_list_friends (rpcsvc_request_t *req, dict_t *dict, int32_t flags)
{
        int32_t                 ret = -1;
        glusterd_conf_t         *priv = NULL;
        glusterd_peerinfo_t     *entry = NULL;
        int32_t                 count = 0;
        dict_t                  *friends = NULL;
        gf1_cli_peer_list_rsp   rsp = {0,};

        priv = THIS->private;
        GF_ASSERT (priv);

        if (!list_empty (&priv->peers)) {
                friends = dict_new ();
                if (!friends) {
                        gf_log ("", GF_LOG_WARNING, "Out of Memory");
                        goto out;
                }
        } else {
                ret = 0;
                goto out;
        }

        if (flags == GF_CLI_LIST_ALL) {
                        list_for_each_entry (entry, &priv->peers, uuid_list) {
                                count++;
                                ret = glusterd_add_peer_detail_to_dict (entry,
                                                                friends, count);
                                if (ret)
                                        goto out;

                        }

                        ret = dict_set_int32 (friends, "count", count);

                        if (ret)
                                goto out;
        }

        ret = dict_allocate_and_serialize (friends, &rsp.friends.friends_val,
                                           &rsp.friends.friends_len);

        if (ret)
                goto out;

        ret = 0;
out:

        if (friends)
                dict_unref (friends);

        rsp.op_ret = ret;

        glusterd_submit_reply (req, &rsp, NULL, 0, NULL,
                               (xdrproc_t)xdr_gf1_cli_peer_list_rsp);
        ret = 0;
        GF_FREE (rsp.friends.friends_val);

        return ret;
}


int
glusterd_friend_remove_notify (glusterd_peerctx_t *peerctx)
{
        int                             ret = -1;
        glusterd_friend_sm_event_t      *new_event = NULL;
        glusterd_peerinfo_t             *peerinfo = peerctx->peerinfo;
        rpcsvc_request_t                *req = peerctx->args.req;
        char                            *errstr = peerctx->errstr;

        GF_ASSERT (peerctx);

        peerinfo = peerctx->peerinfo;
        req = peerctx->args.req;
        errstr = peerctx->errstr;

        ret = glusterd_friend_sm_new_event (GD_FRIEND_EVENT_REMOVE_FRIEND,
                                            &new_event);
        if (!ret) {
                if (!req) {
                        gf_log (THIS->name, GF_LOG_WARNING,
                                "Unable to find the request for responding "
                                "to User (%s)", peerinfo->hostname);
                        goto out;
                }

                glusterd_xfer_cli_probe_resp (req, -1, ENOTCONN, errstr,
                                              peerinfo->hostname, peerinfo->port);

                new_event->peerinfo = peerinfo;
                ret = glusterd_friend_sm_inject_event (new_event);

        } else {
                gf_log ("glusterd", GF_LOG_ERROR,
                        "Unable to create event for removing peer %s",
                        peerinfo->hostname);
        }

out:
        return ret;
}


int
glusterd_peer_rpc_notify (struct rpc_clnt *rpc, void *mydata,
                          rpc_clnt_event_t event,
                          void *data)
{
        xlator_t             *this        = NULL;
        glusterd_conf_t      *conf        = NULL;
        int                   ret         = 0;
        glusterd_peerinfo_t  *peerinfo    = NULL;
        glusterd_peerctx_t   *peerctx     = NULL;
        uuid_t               *peer_uuid   = NULL;
        gf_boolean_t         quorum_action = _gf_false;

        peerctx = mydata;
        if (!peerctx)
                return 0;

        peerinfo = peerctx->peerinfo;
        this = THIS;
        conf = this->private;

        switch (event) {
        case RPC_CLNT_CONNECT:
        {
                gf_log (this->name, GF_LOG_DEBUG, "got RPC_CLNT_CONNECT");
                peerinfo->connected = 1;
                peerinfo->quorum_action = _gf_true;

                ret = glusterd_peer_dump_version (this, rpc, peerctx);
                if (ret)
                        gf_log ("", GF_LOG_ERROR, "glusterd handshake failed");
                break;
        }

        case RPC_CLNT_DISCONNECT:
        {
                gf_log (this->name, GF_LOG_DEBUG, "got RPC_CLNT_DISCONNECT %d",
                        peerinfo->state.state);

                if ((peerinfo->quorum_contrib != QUORUM_DOWN) &&
                    (peerinfo->state.state == GD_FRIEND_STATE_BEFRIENDED)) {
                        peerinfo->quorum_contrib = QUORUM_DOWN;
                        quorum_action = _gf_true;
                        peerinfo->quorum_action = _gf_false;
                }

                // Remove peer if it is not a friend and connection/handshake
                // fails, and notify cli. Happens only during probe.
                if (peerinfo->state.state == GD_FRIEND_STATE_DEFAULT) {
                        glusterd_friend_remove_notify (peerctx);
                        goto out;
                }

                /*
                  local glusterd (thinks that it) is the owner of the cluster
                  lock and 'fails' the operation on the first disconnect from
                  a peer.
                */
                if (peerinfo->connected) {
                        /*TODO: The following is needed till all volume
                         * operations are synctaskized.
                         * */
                        if (is_origin_glusterd ()) {
                                switch (glusterd_op_get_op ()) {
                                case GD_OP_START_VOLUME:
                                case GD_OP_ADD_BRICK:
                                case GD_OP_REMOVE_BRICK:
                                case GD_OP_STATUS_VOLUME:
                                        break;

                                default:
                                        ret = glusterd_op_sm_inject_event
                                              (GD_OP_EVENT_START_UNLOCK, NULL);
                                        if (ret)
                                                gf_log (this->name,
                                                        GF_LOG_ERROR,
                                                        "Unable to enqueue "
                                                        "cluster unlock event");

                                        break;
                                }

                        } else {
                                peer_uuid = GF_CALLOC (1, sizeof (*peer_uuid),
                                                       gf_common_mt_char);

                                if (peer_uuid) {
                                        uuid_copy (*peer_uuid, peerinfo->uuid);
                                        ret = glusterd_op_sm_inject_event
                                              (GD_OP_EVENT_LOCAL_UNLOCK_NO_RESP,
                                               peer_uuid);
                                        if (ret)
                                                gf_log (this->name,
                                                        GF_LOG_ERROR,
                                                        "Unable to enqueue "
                                                        "local lock flush "
                                                        "event.");
                                }
                        }

                }

                peerinfo->connected = 0;
                //default_notify (this, GF_EVENT_CHILD_DOWN, NULL);
                break;
        }
        default:
                gf_log (this->name, GF_LOG_TRACE,
                        "got some other RPC event %d", event);
                ret = 0;
                break;
        }

out:
        glusterd_friend_sm ();
        glusterd_op_sm ();
        if (quorum_action)
                glusterd_do_quorum_action ();
        return ret;
}


static int
glusterd_null (rpcsvc_request_t *req)
{

        return 0;
}

rpcsvc_actor_t gd_svc_peer_actors[] = {
        [GLUSTERD_FRIEND_NULL]    = { "NULL", GLUSTERD_MGMT_NULL, glusterd_null, NULL, 0},
        [GLUSTERD_PROBE_QUERY]    = { "PROBE_QUERY", GLUSTERD_PROBE_QUERY, glusterd_handle_probe_query, NULL, 0},
        [GLUSTERD_FRIEND_ADD]     = { "FRIEND_ADD", GLUSTERD_FRIEND_ADD, glusterd_handle_incoming_friend_req, NULL, 0},
        [GLUSTERD_FRIEND_REMOVE]  = { "FRIEND_REMOVE", GLUSTERD_FRIEND_REMOVE, glusterd_handle_incoming_unfriend_req, NULL, 0},
        [GLUSTERD_FRIEND_UPDATE]  = { "FRIEND_UPDATE", GLUSTERD_FRIEND_UPDATE, glusterd_handle_friend_update, NULL, 0},
};

struct rpcsvc_program gd_svc_peer_prog = {
        .progname  = "GlusterD svc peer",
        .prognum   = GD_FRIEND_PROGRAM,
        .progver   = GD_FRIEND_VERSION,
        .numactors = GLUSTERD_FRIEND_MAXVALUE,
        .actors    = gd_svc_peer_actors,
	.synctask  = _gf_false,
};
