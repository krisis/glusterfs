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
#include "glusterd-sm.h"
#include "glusterd-op-sm.h"
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

struct args_pack {
    dict_t *dict;
    int vol_count;
    int opt_count;
};

static int
_build_option_key (dict_t *d, char *k, data_t *v, void *tmp)
{
        char                    reconfig_key[256] = {0, };
        struct args_pack        *pack             = NULL;
        int                     ret               = -1;

        pack = tmp;
        if (strcmp (k, GLUSTERD_GLOBAL_OPT_VERSION) == 0)
                return 0;
        snprintf (reconfig_key, 256, "volume%d.option.%s",
                  pack->vol_count, k);
        ret = dict_set_str (pack->dict, reconfig_key, v->data);
        if (0 == ret)
                pack->opt_count++;

        return 0;
}

int
glusterd_add_volume_detail_to_dict (glusterd_volinfo_t *volinfo,
                                    dict_t  *volumes, int count)
{

        int                     ret = -1;
        char                    key[256] = {0, };
        glusterd_brickinfo_t    *brickinfo = NULL;
        char                    *buf = NULL;
        int                     i = 1;
        dict_t                  *dict = NULL;
        glusterd_conf_t         *priv = NULL;
        char                    *volume_id_str  = NULL;
        struct args_pack        pack = {0,};
        xlator_t                *this = NULL;


        GF_ASSERT (volinfo);
        GF_ASSERT (volumes);

        this = THIS;
        priv = this->private;

        GF_ASSERT (priv);

        snprintf (key, 256, "volume%d.name", count);
        ret = dict_set_str (volumes, key, volinfo->volname);
        if (ret)
                goto out;

        snprintf (key, 256, "volume%d.type", count);
        ret = dict_set_int32 (volumes, key, volinfo->type);
        if (ret)
                goto out;

        snprintf (key, 256, "volume%d.status", count);
        ret = dict_set_int32 (volumes, key, volinfo->status);
        if (ret)
                goto out;

        snprintf (key, 256, "volume%d.brick_count", count);
        ret = dict_set_int32 (volumes, key, volinfo->brick_count);
        if (ret)
                goto out;

        snprintf (key, 256, "volume%d.dist_count", count);
        ret = dict_set_int32 (volumes, key, volinfo->dist_leaf_count);
        if (ret)
                goto out;

        snprintf (key, 256, "volume%d.stripe_count", count);
        ret = dict_set_int32 (volumes, key, volinfo->stripe_count);
        if (ret)
                goto out;

        snprintf (key, 256, "volume%d.replica_count", count);
        ret = dict_set_int32 (volumes, key, volinfo->replica_count);
        if (ret)
                goto out;

        snprintf (key, 256, "volume%d.transport", count);
        ret = dict_set_int32 (volumes, key, volinfo->transport_type);
        if (ret)
                goto out;

        volume_id_str = gf_strdup (uuid_utoa (volinfo->volume_id));
        if (!volume_id_str)
                goto out;

        snprintf (key, sizeof (key), "volume%d.volume_id", count);
        ret = dict_set_dynstr (volumes, key, volume_id_str);
        if (ret)
                goto out;

        snprintf (key, 256, "volume%d.rebalance", count);
        ret = dict_set_int32 (volumes, key, volinfo->rebal.defrag_cmd);
        if (ret)
                goto out;

#ifdef HAVE_BD_XLATOR
        snprintf (key, 256, "volume%d.backend", count);
        ret = dict_set_int32 (volumes, key, volinfo->backend);
        if (ret)
                goto out;
#endif

        list_for_each_entry (brickinfo, &volinfo->bricks, brick_list) {
                char    brick[1024] = {0,};
                snprintf (key, 256, "volume%d.brick%d", count, i);
                snprintf (brick, 1024, "%s:%s", brickinfo->hostname,
                          brickinfo->path);
                buf = gf_strdup (brick);
                ret = dict_set_dynstr (volumes, key, buf);
                if (ret)
                        goto out;
                i++;
        }

        dict = volinfo->dict;
        if (!dict) {
                ret = 0;
                goto out;
        }

        pack.dict = volumes;
        pack.vol_count = count;
        pack.opt_count = 0;
        dict_foreach (dict, _build_option_key, (void *) &pack);
        dict_foreach (priv->opts, _build_option_key, &pack);

        snprintf (key, 256, "volume%d.opt_count", pack.vol_count);
        ret = dict_set_int32 (volumes, key, pack.opt_count);
out:
        return ret;
}

int
glusterd_handle_cli_probe (rpcsvc_request_t *req)
{
        int32_t                         ret = -1;
        gf1_cli_probe_req               cli_req = {0,};
        glusterd_peerinfo_t             *peerinfo = NULL;
        gf_boolean_t                    run_fsm = _gf_true;
        xlator_t                        *this = NULL;
        char                            *bind_name = NULL;

        GF_ASSERT (req);
        this = THIS;

        ret = xdr_to_generic (req->msg[0], &cli_req,
                              (xdrproc_t)xdr_gf1_cli_probe_req);
        if (ret < 0)  {
                //failed to decode msg;
                gf_log ("", GF_LOG_ERROR, "xdr decoding error");
                req->rpc_err = GARBAGE_ARGS;
                goto out;
        }

        if (glusterd_is_any_volume_in_server_quorum (this) &&
            !does_gd_meet_server_quorum (this)) {
                glusterd_xfer_cli_probe_resp (req, -1, GF_PROBE_QUORUM_NOT_MET,
                                              NULL,
                                              cli_req.hostname, cli_req.port);
                gf_log (this->name, GF_LOG_ERROR, "Quorum does not meet, "
                        "rejecting operation");
                ret = 0;
                goto out;
        }

        gf_cmd_log ("peer probe", " on host %s:%d", cli_req.hostname,
                    cli_req.port);
        gf_log ("glusterd", GF_LOG_INFO, "Received CLI probe req %s %d",
                cli_req.hostname, cli_req.port);

        if (dict_get_str(this->options,"transport.socket.bind-address",
                         &bind_name) == 0) {
                gf_log ("glusterd", GF_LOG_DEBUG,
                        "only checking probe address vs. bind address");
                ret = glusterd_is_same_address(bind_name,cli_req.hostname);
        }
        else {
                ret = glusterd_is_local_addr(cli_req.hostname);
        }
        if (ret) {
                glusterd_xfer_cli_probe_resp (req, 0, GF_PROBE_LOCALHOST, NULL,
                                              cli_req.hostname, cli_req.port);
                ret = 0;
                goto out;
        }

        if (!(ret = glusterd_friend_find_by_hostname(cli_req.hostname,
                                         &peerinfo))) {
                if (strcmp (peerinfo->hostname, cli_req.hostname) == 0) {

                        gf_log ("glusterd", GF_LOG_DEBUG, "Probe host %s port "
                                "%d already a peer", cli_req.hostname,
                                cli_req.port);
                        glusterd_xfer_cli_probe_resp (req, 0, GF_PROBE_FRIEND,
                                                      NULL, cli_req.hostname,
                                                      cli_req.port);
                        goto out;
                }
        }
        ret = glusterd_probe_begin (req, cli_req.hostname, cli_req.port);

        gf_cmd_log ("peer probe","on host %s:%d %s",cli_req.hostname,
                    cli_req.port, (ret) ? "FAILED" : "SUCCESS");

        if (ret == GLUSTERD_CONNECTION_AWAITED) {
                //fsm should be run after connection establishes
                run_fsm = _gf_false;
                ret = 0;
        }
out:
        free (cli_req.hostname);//its malloced by xdr

        if (run_fsm) {
                glusterd_friend_sm ();
                glusterd_op_sm ();
        }

        return ret;
}

int
glusterd_handle_cli_deprobe (rpcsvc_request_t *req)
{
        int32_t                         ret = -1;
        gf1_cli_deprobe_req             cli_req = {0,};
        uuid_t                          uuid = {0};
        int                             op_errno = 0;
        xlator_t                        *this = NULL;
        glusterd_conf_t                 *priv = NULL;

        this = THIS;
        GF_ASSERT (this);
        priv = this->private;
        GF_ASSERT (priv);
        GF_ASSERT (req);

        ret = xdr_to_generic (req->msg[0], &cli_req,
                              (xdrproc_t)xdr_gf1_cli_deprobe_req);
        if (ret < 0) {
                //failed to decode msg;
                req->rpc_err = GARBAGE_ARGS;
                goto out;
        }

        gf_log ("glusterd", GF_LOG_INFO, "Received CLI deprobe req");

        ret = glusterd_hostname_to_uuid (cli_req.hostname, uuid);
        if (ret) {
                op_errno = GF_DEPROBE_NOT_FRIEND;
                goto out;
        }

        if (!uuid_compare (uuid, MY_UUID)) {
                op_errno = GF_DEPROBE_LOCALHOST;
                ret = -1;
                goto out;
        }

        if (!(cli_req.flags & GF_CLI_FLAG_OP_FORCE)) {
                if (!uuid_is_null (uuid)) {
                        /* Check if peers are connected, except peer being detached*/
                        if (!glusterd_chk_peers_connected_befriended (uuid)) {
                                ret = -1;
                                op_errno = GF_DEPROBE_FRIEND_DOWN;
                                goto out;
                        }
                        ret = glusterd_all_volume_cond_check (
                                                 glusterd_friend_brick_belongs,
                                                 -1, &uuid);
                        if (ret) {
                                op_errno = GF_DEPROBE_BRICK_EXIST;
                                goto out;
                        }
                }

                if (glusterd_is_any_volume_in_server_quorum (this) &&
                    !does_gd_meet_server_quorum (this)) {
                        gf_log (this->name, GF_LOG_ERROR, "Quorum does not "
                                "meet, rejecting operation");
                        ret = -1;
                        op_errno = GF_DEPROBE_QUORUM_NOT_MET;
                        goto out;
                }
        }

        if (!uuid_is_null (uuid)) {
                ret = glusterd_deprobe_begin (req, cli_req.hostname,
                                              cli_req.port, uuid);
        } else {
                ret = glusterd_deprobe_begin (req, cli_req.hostname,
                                              cli_req.port, NULL);
        }

        gf_cmd_log ("peer deprobe", "on host %s:%d %s", cli_req.hostname,
                    cli_req.port, (ret) ? "FAILED" : "SUCCESS");
out:
        if (ret) {
                ret = glusterd_xfer_cli_deprobe_resp (req, ret, op_errno, NULL,
                                                      cli_req.hostname);
        }

        free (cli_req.hostname);//malloced by xdr

        glusterd_friend_sm ();
        glusterd_op_sm ();

        return ret;
}

int
glusterd_handle_cli_list_friends (rpcsvc_request_t *req)
{
        int32_t                         ret = -1;
        gf1_cli_peer_list_req           cli_req = {0,};
        dict_t                          *dict = NULL;

        GF_ASSERT (req);

        ret = xdr_to_generic (req->msg[0], &cli_req,
                              (xdrproc_t)xdr_gf1_cli_peer_list_req);
        if (ret < 0) {
                //failed to decode msg;
                req->rpc_err = GARBAGE_ARGS;
                goto out;
        }

        gf_log ("glusterd", GF_LOG_INFO, "Received cli list req");

        if (cli_req.dict.dict_len) {
                /* Unserialize the dictionary */
                dict  = dict_new ();

                ret = dict_unserialize (cli_req.dict.dict_val,
                                        cli_req.dict.dict_len,
                                        &dict);
                if (ret < 0) {
                        gf_log ("glusterd", GF_LOG_ERROR,
                                "failed to "
                                "unserialize req-buffer to dictionary");
                        goto out;
                } else {
                        dict->extra_stdfree = cli_req.dict.dict_val;
                }
        }

        ret = glusterd_list_friends (req, dict, cli_req.flags);

out:
        if (dict)
                dict_unref (dict);

        glusterd_friend_sm ();
        glusterd_op_sm ();

        return ret;
}

int
glusterd_handle_cli_get_volume (rpcsvc_request_t *req)
{
        int32_t                         ret = -1;
        gf_cli_req                      cli_req = {{0,}};
        dict_t                          *dict = NULL;
        int32_t                         flags = 0;

        GF_ASSERT (req);

        ret = xdr_to_generic (req->msg[0], &cli_req, (xdrproc_t)xdr_gf_cli_req);
        if (ret < 0) {
                //failed to decode msg;
                req->rpc_err = GARBAGE_ARGS;
                goto out;
        }

        gf_log ("glusterd", GF_LOG_INFO, "Received get vol req");

        if (cli_req.dict.dict_len) {
                /* Unserialize the dictionary */
                dict  = dict_new ();

                ret = dict_unserialize (cli_req.dict.dict_val,
                                        cli_req.dict.dict_len,
                                        &dict);
                if (ret < 0) {
                        gf_log ("glusterd", GF_LOG_ERROR,
                                "failed to "
                                "unserialize req-buffer to dictionary");
                        goto out;
                } else {
                        dict->extra_stdfree = cli_req.dict.dict_val;
                }
        }

        ret = dict_get_int32 (dict, "flags", &flags);
        if (ret) {
                gf_log (THIS->name, GF_LOG_ERROR, "failed to get flags");
                goto out;
        }

        ret = glusterd_get_volumes (req, dict, flags);

out:
        if (dict)
                dict_unref (dict);

        glusterd_friend_sm ();
        glusterd_op_sm ();

        return ret;
}

#ifdef HAVE_BD_XLATOR
int
glusterd_handle_cli_bd_op (rpcsvc_request_t *req)
{
        int32_t          ret        = -1;
        gf_cli_req       cli_req    = { {0,} };
        dict_t           *dict      = NULL;
        char             *volname   = NULL;
        char             op_errstr[2048] = {0,};
        glusterd_op_t    cli_op     = GD_OP_BD_OP;

        GF_ASSERT (req);

        ret = xdr_to_generic (req->msg[0], &cli_req, (xdrproc_t)xdr_gf_cli_req);
        if (ret < 0) {
                /* failed to decode msg */
                req->rpc_err = GARBAGE_ARGS;
                goto out;
        }

        gf_log ("glusterd", GF_LOG_DEBUG, "Received bd op req");

        if (cli_req.dict.dict_len) {
                /* Unserialize the dictionary */
                dict  = dict_new ();

                ret = dict_unserialize (cli_req.dict.dict_val,
                                        cli_req.dict.dict_len,
                                        &dict);
                if (ret < 0) {
                        gf_log ("glusterd", GF_LOG_ERROR,
                                "failed to "
                                "unserialize req-buffer to dictionary");
                        goto out;
                } else {
                        dict->extra_stdfree = cli_req.dict.dict_val;
                }
        }

        ret = dict_get_str (dict, "volname", &volname);
        if (ret) {
                gf_log (THIS->name, GF_LOG_ERROR,
                                "failed to get volname");
                goto out;
        }

        ret = glusterd_op_begin (req, GD_OP_BD_OP, dict, op_errstr,
                                 sizeof (op_errstr));
        gf_cmd_log ("bd op: %s", ((ret == 0) ? "SUCCESS": "FAILED"));
out:
        if (ret && dict)
                dict_unref (dict);

        glusterd_friend_sm ();
        glusterd_op_sm ();

        if (ret) {
                if (op_errstr[0] == '\0')
                        snprintf (op_errstr, sizeof (op_errstr),
                                  "Operation failed");
                ret = glusterd_op_send_cli_response (cli_op, ret, 0,
                                req, NULL, op_errstr);
        }

        return ret;
}
#endif

int
glusterd_handle_cli_uuid_reset (rpcsvc_request_t *req)
{
        int                     ret     = -1;
        dict_t                  *dict   = NULL;
        xlator_t                *this   = NULL;
        glusterd_conf_t         *priv   = NULL;
        uuid_t                  uuid    = {0};
        gf_cli_rsp              rsp     = {0,};
        gf_cli_req              cli_req = {{0,}};
        char                    msg_str[2048] = {0,};

        GF_ASSERT (req);

        this = THIS;
        priv = this->private;
        GF_ASSERT (priv);

        ret = xdr_to_generic (req->msg[0], &cli_req, (xdrproc_t)xdr_gf_cli_req);
        if (ret < 0) {
                //failed to decode msg;
                req->rpc_err = GARBAGE_ARGS;
                goto out;
        }

        gf_log ("glusterd", GF_LOG_DEBUG, "Received uuid reset req");

        if (cli_req.dict.dict_len) {
                /* Unserialize the dictionary */
                dict  = dict_new ();

                ret = dict_unserialize (cli_req.dict.dict_val,
                                        cli_req.dict.dict_len,
                                        &dict);
                if (ret < 0) {
                        gf_log ("glusterd", GF_LOG_ERROR,
                                "failed to "
                                "unserialize req-buffer to dictionary");
                        snprintf (msg_str, sizeof (msg_str), "Unable to decode "
                                  "the buffer");
                        goto out;
                } else {
                        dict->extra_stdfree = cli_req.dict.dict_val;
                }
        }

        /* In the above section if dict_unserialize is successful, ret is set
         * to zero.
         */
        ret = -1;
        // Do not allow peer reset if there are any volumes in the cluster
        if (!list_empty (&priv->volumes)) {
                snprintf (msg_str, sizeof (msg_str), "volumes are already "
                          "present in the cluster. Resetting uuid is not "
                          "allowed");
                gf_log (this->name, GF_LOG_WARNING, "%s", msg_str);
                goto out;
        }

        // Do not allow peer reset if trusted storage pool is already formed
        if (!list_empty (&priv->peers)) {
                snprintf (msg_str, sizeof (msg_str),"trusted storage pool "
                          "has been already formed. Please detach this peer "
                          "from the pool and reset its uuid.");
                gf_log (this->name, GF_LOG_WARNING, "%s", msg_str);
                goto out;
        }

        uuid_copy (uuid, priv->uuid);
        ret = glusterd_uuid_generate_save ();

        if (!uuid_compare (uuid, MY_UUID)) {
                snprintf (msg_str, sizeof (msg_str), "old uuid and the new uuid"
                          " are same. Try gluster peer reset again");
                gf_log (this->name, GF_LOG_ERROR, "%s", msg_str);
                ret = -1;
                goto out;
        }

out:
        if (ret) {
                rsp.op_ret = -1;
                if (msg_str[0] == '\0')
                        snprintf (msg_str, sizeof (msg_str), "Operation "
                                  "failed");
                rsp.op_errstr = msg_str;
                ret = 0;
        } else {
                rsp.op_errstr = "";
        }

        glusterd_to_cli (req, &rsp, NULL, 0, NULL,
                         (xdrproc_t)xdr_gf_cli_rsp, dict);

        return ret;
}

int
glusterd_handle_cli_list_volume (rpcsvc_request_t *req)
{
        int                     ret = -1;
        dict_t                  *dict = NULL;
        glusterd_conf_t         *priv = NULL;
        glusterd_volinfo_t      *volinfo = NULL;
        int                     count = 0;
        char                    key[1024] = {0,};
        gf_cli_rsp              rsp = {0,};

        GF_ASSERT (req);

        priv = THIS->private;
        GF_ASSERT (priv);

        dict = dict_new ();
        if (!dict)
                goto out;

        list_for_each_entry (volinfo, &priv->volumes, vol_list) {
                memset (key, 0, sizeof (key));
                snprintf (key, sizeof (key), "volume%d", count);
                ret = dict_set_str (dict, key, volinfo->volname);
                if (ret)
                        goto out;
                count++;
        }

        ret = dict_set_int32 (dict, "count", count);
        if (ret)
                goto out;

        ret = dict_allocate_and_serialize (dict, &rsp.dict.dict_val,
                                           &rsp.dict.dict_len);
        if (ret)
                goto out;

        ret = 0;

out:
        rsp.op_ret = ret;
        if (ret)
                rsp.op_errstr = "Error listing volumes";
        else
                rsp.op_errstr = "";

        glusterd_submit_reply (req, &rsp, NULL, 0, NULL,
                                     (xdrproc_t)xdr_gf_cli_rsp);
        ret = 0;

        if (dict)
                dict_unref (dict);

        glusterd_friend_sm ();
        glusterd_op_sm ();

        return ret;
}

int32_t
glusterd_op_txn_begin (rpcsvc_request_t *req, glusterd_op_t op, void *ctx,
                       char *err_str, size_t err_len)
{
        int32_t                  ret    = -1;
        xlator_t                *this   = NULL;
        glusterd_conf_t         *priv   = NULL;
        int32_t                  locked = 0;

        GF_ASSERT (req);
        GF_ASSERT ((op > GD_OP_NONE) && (op < GD_OP_MAX));
        GF_ASSERT (NULL != ctx);

        this = THIS;
        GF_ASSERT (this);
        priv = this->private;
        GF_ASSERT (priv);

        ret = glusterd_lock (MY_UUID);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR,
                        "Unable to acquire lock on localhost, ret: %d", ret);
                snprintf (err_str, err_len, "Another transaction is in progress. "
                          "Please try again after sometime.");
                goto out;
        }

        synclock_lock (&priv->big_lock);
        locked = 1;
        gf_log (this->name, GF_LOG_DEBUG, "Acquired lock on localhost");

        ret = glusterd_op_sm_inject_event (GD_OP_EVENT_START_LOCK, NULL);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "Failed to acquire cluster"
                        " lock.");
                goto out;
        }

        glusterd_op_set_op (op);
        glusterd_op_set_ctx (ctx);
        glusterd_op_set_req (req);


out:
        if (locked && ret) {
                synclock_unlock (&priv->big_lock);
                glusterd_unlock (MY_UUID);
        }

        gf_log (this->name, GF_LOG_DEBUG, "Returning %d", ret);
        return ret;
}

int32_t
glusterd_op_begin (rpcsvc_request_t *req, glusterd_op_t op, void *ctx,
                   char *err_str, size_t err_len)
{
        int             ret = -1;

        ret = glusterd_op_txn_begin (req, op, ctx, err_str, err_len);

        return ret;
}

int
glusterd_handle_reset_volume (rpcsvc_request_t *req)
{
        int32_t                         ret = -1;
        gf_cli_req                      cli_req = {{0,}};
        dict_t                          *dict = NULL;
        glusterd_op_t                   cli_op = GD_OP_RESET_VOLUME;
        char                            *volname = NULL;
        char                            err_str[2048] = {0,};
        xlator_t                        *this = NULL;

        GF_ASSERT (req);
        this = THIS;
        GF_ASSERT (this);

        ret = xdr_to_generic (req->msg[0], &cli_req, (xdrproc_t)xdr_gf_cli_req);
        if (ret < 0) {
                snprintf (err_str, sizeof (err_str), "Failed to decode request "
                          "received from cli");
                gf_log (this->name, GF_LOG_ERROR, "%s", err_str);
                req->rpc_err = GARBAGE_ARGS;
                goto out;
        }

        if (cli_req.dict.dict_len) {
                /* Unserialize the dictionary */
                dict  = dict_new ();

                ret = dict_unserialize (cli_req.dict.dict_val,
                                        cli_req.dict.dict_len,
                                        &dict);
                if (ret < 0) {
                        gf_log (this->name, GF_LOG_ERROR, "failed to "
                                    "unserialize req-buffer to dictionary");
                        snprintf (err_str, sizeof (err_str), "Unable to decode "
                                  "the command");
                        goto out;
                } else {
                        dict->extra_stdfree = cli_req.dict.dict_val;
                }
        }

        ret = dict_get_str (dict, "volname", &volname);
        if (ret) {
                snprintf (err_str, sizeof (err_str), "Failed to get volume "
                          "name");
                gf_log (this->name, GF_LOG_ERROR, "%s", err_str);
                goto out;
        }
        gf_log (this->name, GF_LOG_DEBUG, "Received volume reset request for "
                "volume %s", volname);

        ret = glusterd_op_begin_synctask (req, GD_OP_RESET_VOLUME, dict);

out:
        if (ret) {
                if (err_str[0] == '\0')
                        snprintf (err_str, sizeof (err_str),
                                  "Operation failed");
                ret = glusterd_op_send_cli_response (cli_op, ret, 0, req,
                                                     dict, err_str);
        }

        return ret;
}


int
glusterd_handle_set_volume (rpcsvc_request_t *req)
{
        int32_t                         ret = -1;
        gf_cli_req                      cli_req = {{0,}};
        dict_t                          *dict = NULL;
        glusterd_op_t                   cli_op = GD_OP_SET_VOLUME;
        char                            *key = NULL;
        char                            *value = NULL;
        char                            *volname = NULL;
        char                            *op_errstr = NULL;
        gf_boolean_t                    help = _gf_false;
        char                            err_str[2048] = {0,};
        xlator_t                        *this = NULL;

        this = THIS;
        GF_ASSERT (this);

        GF_ASSERT (req);

        ret = xdr_to_generic (req->msg[0], &cli_req, (xdrproc_t)xdr_gf_cli_req);
        if (ret < 0) {
                snprintf (err_str, sizeof (err_str), "Failed to decode "
                          "request received from cli");
                gf_log (this->name, GF_LOG_ERROR, "%s", err_str);
                req->rpc_err = GARBAGE_ARGS;
                goto out;
        }

        if (cli_req.dict.dict_len) {
                /* Unserialize the dictionary */
                dict  = dict_new ();

                ret = dict_unserialize (cli_req.dict.dict_val,
                                        cli_req.dict.dict_len,
                                        &dict);
                if (ret < 0) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "failed to "
                                "unserialize req-buffer to dictionary");
                        snprintf (err_str, sizeof (err_str), "Unable to decode "
                                  "the command");
                        goto out;
                } else {
                        dict->extra_stdfree = cli_req.dict.dict_val;
                }
        }

        ret = dict_get_str (dict, "volname", &volname);
        if (ret) {
                snprintf (err_str, sizeof (err_str), "Failed to get volume "
                          "name while handling volume set command");
                gf_log (this->name, GF_LOG_ERROR, "%s", err_str);
                goto out;
        }

        if (strcmp (volname, "help") == 0 ||
            strcmp (volname, "help-xml") == 0) {
                ret = glusterd_volset_help (dict, &op_errstr);
                help = _gf_true;
                goto out;
        }

        ret = dict_get_str (dict, "key1", &key);
        if (ret) {
                snprintf (err_str, sizeof (err_str), "Failed to get key while"
                          " handling volume set for %s", volname);
                gf_log (this->name, GF_LOG_ERROR, "%s", err_str);
                goto out;
        }

        ret = dict_get_str (dict, "value1", &value);
        if (ret) {
                snprintf (err_str, sizeof (err_str), "Failed to get value while"
                          " handling volume set for %s", volname);
                gf_log (this->name, GF_LOG_ERROR, "%s", err_str);
                goto out;
        }
        gf_log (this->name, GF_LOG_DEBUG, "Received volume set request for "
                "volume %s", volname);

        ret = glusterd_op_begin_synctask (req, GD_OP_SET_VOLUME, dict);

out:
        if (help)
                ret = glusterd_op_send_cli_response (cli_op, ret, 0, req, dict,
                                                     (op_errstr)? op_errstr:"");
        else if (ret) {
                if (err_str[0] == '\0')
                        snprintf (err_str, sizeof (err_str),
                                  "Operation failed");
                ret = glusterd_op_send_cli_response (cli_op, ret, 0, req,
                                                     dict, err_str);
        }
        if (op_errstr)
                GF_FREE (op_errstr);

        return ret;
}

int
glusterd_handle_sync_volume (rpcsvc_request_t *req)
{
        int32_t                          ret     = -1;
        gf_cli_req                       cli_req = {{0,}};
        dict_t                           *dict = NULL;
        gf_cli_rsp                       cli_rsp = {0.};
        char                             msg[2048] = {0,};
        char                             *volname = NULL;
        gf1_cli_sync_volume              flags = 0;
        char                             *hostname = NULL;
        xlator_t                         *this = NULL;

        GF_ASSERT (req);
        this = THIS;
        GF_ASSERT (this);

        ret = xdr_to_generic (req->msg[0], &cli_req, (xdrproc_t)xdr_gf_cli_req);
        if (ret < 0) {
                //failed to decode msg;
                req->rpc_err = GARBAGE_ARGS;
                goto out;
        }

        if (cli_req.dict.dict_len) {
                /* Unserialize the dictionary */
                dict  = dict_new ();

                ret = dict_unserialize (cli_req.dict.dict_val,
                                        cli_req.dict.dict_len,
                                        &dict);
                if (ret < 0) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "failed to "
                                "unserialize req-buffer to dictionary");
                        snprintf (msg, sizeof (msg), "Unable to decode the "
                                  "command");
                        goto out;
                } else {
                        dict->extra_stdfree = cli_req.dict.dict_val;
                }
        }

        ret = dict_get_str (dict, "hostname", &hostname);
        if (ret) {
                snprintf (msg, sizeof (msg), "Failed to get hostname");
                gf_log (this->name, GF_LOG_ERROR, "%s", msg);
                goto out;
        }

        ret = dict_get_str (dict, "volname", &volname);
        if (ret) {
                ret = dict_get_int32 (dict, "flags", (int32_t*)&flags);
                if (ret) {
                        snprintf (msg, sizeof (msg), "Failed to get volume name"
                                  " or flags");
                        gf_log (this->name, GF_LOG_ERROR, "%s", msg);
                        goto out;
                }
        }

        gf_log (this->name, GF_LOG_INFO, "Received volume sync req "
                "for volume %s", (flags & GF_CLI_SYNC_ALL) ? "all" : volname);

        if (glusterd_is_local_addr (hostname)) {
                ret = -1;
                snprintf (msg, sizeof (msg), "sync from localhost"
                          " not allowed");
                gf_log (this->name, GF_LOG_ERROR, "%s", msg);
                goto out;
        }

        ret = glusterd_op_begin_synctask (req, GD_OP_SYNC_VOLUME, dict);

out:
        if (ret) {
                cli_rsp.op_ret = -1;
                cli_rsp.op_errstr = msg;
                if (msg[0] == '\0')
                        snprintf (msg, sizeof (msg), "Operation failed");
                glusterd_to_cli (req, &cli_rsp, NULL, 0, NULL,
                                 (xdrproc_t)xdr_gf_cli_rsp, dict);

                ret = 0; //sent error to cli, prevent second reply
        }

        return ret;
}

int
glusterd_fsm_log_send_resp (rpcsvc_request_t *req, int op_ret,
                            char *op_errstr, dict_t *dict)
{

        int                             ret = -1;
        gf1_cli_fsm_log_rsp             rsp = {0};

        GF_ASSERT (req);
        GF_ASSERT (op_errstr);

        rsp.op_ret = op_ret;
        rsp.op_errstr = op_errstr;
        if (rsp.op_ret == 0)
                ret = dict_allocate_and_serialize (dict, &rsp.fsm_log.fsm_log_val,
                                                &rsp.fsm_log.fsm_log_len);

        ret = glusterd_submit_reply (req, &rsp, NULL, 0, NULL,
                                     (xdrproc_t)xdr_gf1_cli_fsm_log_rsp);
        GF_FREE (rsp.fsm_log.fsm_log_val);

        gf_log ("glusterd", GF_LOG_DEBUG, "Responded, ret: %d", ret);

        return 0;
}

int
glusterd_handle_fsm_log (rpcsvc_request_t *req)
{
        int32_t                         ret = -1;
        gf1_cli_fsm_log_req             cli_req = {0,};
        dict_t                          *dict = NULL;
        glusterd_sm_tr_log_t            *log = NULL;
        xlator_t                        *this = NULL;
        glusterd_conf_t                 *conf = NULL;
        char                            msg[2048] = {0};
        glusterd_peerinfo_t             *peerinfo = NULL;

        GF_ASSERT (req);

        ret = xdr_to_generic (req->msg[0], &cli_req,
                              (xdrproc_t)xdr_gf1_cli_fsm_log_req);
        if (ret < 0) {
                //failed to decode msg;
                req->rpc_err = GARBAGE_ARGS;
                snprintf (msg, sizeof (msg), "Garbage request");
                goto out;
        }

        if (strcmp ("", cli_req.name) == 0) {
                this = THIS;
                conf = this->private;
                log = &conf->op_sm_log;
        } else {
                ret = glusterd_friend_find_by_hostname (cli_req.name,
                                                        &peerinfo);
                if (ret) {
                        snprintf (msg, sizeof (msg), "%s is not a peer",
                                  cli_req.name);
                        goto out;
                }
                log = &peerinfo->sm_log;
        }

        dict = dict_new ();
        if (!dict) {
                ret = -1;
                goto out;
        }

        ret = glusterd_sm_tr_log_add_to_dict (dict, log);
out:
        (void)glusterd_fsm_log_send_resp (req, ret, msg, dict);
        free (cli_req.name);//malloced by xdr
        if (dict)
                dict_unref (dict);

        glusterd_friend_sm ();
        glusterd_op_sm ();

        return 0;//send 0 to avoid double reply
}


int
glusterd_handle_cli_profile_volume (rpcsvc_request_t *req)
{
        int32_t                         ret     = -1;
        gf_cli_req                      cli_req = {{0,}};
        dict_t                          *dict = NULL;
        glusterd_op_t                   cli_op = GD_OP_PROFILE_VOLUME;
        char                            *volname = NULL;
        int32_t                         op = 0;
        char                            err_str[2048] = {0,};
        xlator_t                        *this = NULL;

        GF_ASSERT (req);
        this = THIS;
        GF_ASSERT (this);

        ret = xdr_to_generic (req->msg[0], &cli_req, (xdrproc_t)xdr_gf_cli_req);
        if (ret < 0) {
                //failed to decode msg;
                req->rpc_err = GARBAGE_ARGS;
                goto out;
        }

        if (cli_req.dict.dict_len > 0) {
                dict = dict_new();
                if (!dict)
                        goto out;
                dict_unserialize (cli_req.dict.dict_val,
                                  cli_req.dict.dict_len, &dict);
        }

        ret = dict_get_str (dict, "volname", &volname);
        if (ret) {
                snprintf (err_str, sizeof (err_str), "Unable to get volume "
                          "name");
                gf_log (this->name, GF_LOG_ERROR, "%s", err_str);
                goto out;
        }

        gf_log (this->name, GF_LOG_INFO, "Received volume profile req "
                "for volume %s", volname);
        ret = dict_get_int32 (dict, "op", &op);
        if (ret) {
                snprintf (err_str, sizeof (err_str), "Unable to get operation");
                gf_log (this->name, GF_LOG_ERROR, "%s", err_str);
                goto out;
        }

        ret = glusterd_op_begin (req, cli_op, dict, err_str, sizeof (err_str));

out:
        glusterd_friend_sm ();
        glusterd_op_sm ();

        free (cli_req.dict.dict_val);

        if (ret) {
                if (err_str[0] == '\0')
                        snprintf (err_str, sizeof (err_str),
                                  "Operation failed");
                ret = glusterd_op_send_cli_response (cli_op, ret, 0, req,
                                                     dict, err_str);
        }

        gf_log (this->name, GF_LOG_DEBUG, "Returning %d", ret);
        return ret;
}

int
glusterd_handle_getwd (rpcsvc_request_t *req)
{
        int32_t                 ret = -1;
        gf1_cli_getwd_rsp     rsp = {0,};
        glusterd_conf_t         *priv = NULL;

        GF_ASSERT (req);

        priv = THIS->private;
        GF_ASSERT (priv);

        gf_log ("glusterd", GF_LOG_INFO, "Received getwd req");

        rsp.wd = priv->workdir;

        glusterd_submit_reply (req, &rsp, NULL, 0, NULL,
                               (xdrproc_t)xdr_gf1_cli_getwd_rsp);
        ret = 0;

        glusterd_friend_sm ();
        glusterd_op_sm ();

        return ret;
}


int
glusterd_handle_mount (rpcsvc_request_t *req)
{
        gf1_cli_mount_req mnt_req = {0,};
        gf1_cli_mount_rsp rsp     = {0,};
        dict_t *dict              = NULL;
        int ret                   = 0;

        GF_ASSERT (req);

        ret = xdr_to_generic (req->msg[0], &mnt_req,
                              (xdrproc_t)xdr_gf1_cli_mount_req);
        if (ret < 0) {
                //failed to decode msg;
                req->rpc_err = GARBAGE_ARGS;
                rsp.op_ret = -1;
                rsp.op_errno = EINVAL;
                goto out;
        }

        gf_log ("glusterd", GF_LOG_INFO, "Received mount req");

        if (mnt_req.dict.dict_len) {
                /* Unserialize the dictionary */
                dict  = dict_new ();

                ret = dict_unserialize (mnt_req.dict.dict_val,
                                        mnt_req.dict.dict_len,
                                        &dict);
                if (ret < 0) {
                        gf_log ("glusterd", GF_LOG_ERROR,
                                "failed to "
                                "unserialize req-buffer to dictionary");
                        rsp.op_ret = -1;
                        rsp.op_errno = -EINVAL;
                        goto out;
                } else {
                        dict->extra_stdfree = mnt_req.dict.dict_val;
                }
        }

        rsp.op_ret = glusterd_do_mount (mnt_req.label, dict,
                                        &rsp.path, &rsp.op_errno);

 out:
        if (!rsp.path)
                rsp.path = "";

        glusterd_submit_reply (req, &rsp, NULL, 0, NULL,
                               (xdrproc_t)xdr_gf1_cli_mount_rsp);
        ret = 0;

        if (dict)
                dict_unref (dict);
        if (*rsp.path)
                GF_FREE (rsp.path);

        glusterd_friend_sm ();
        glusterd_op_sm ();

        return ret;
}

int
glusterd_handle_umount (rpcsvc_request_t *req)
{
        gf1_cli_umount_req umnt_req = {0,};
        gf1_cli_umount_rsp rsp      = {0,};
        char *mountbroker_root      = NULL;
        char mntp[PATH_MAX]         = {0,};
        char *path                  = NULL;
        runner_t runner             = {0,};
        int ret                     = 0;
        xlator_t *this              = THIS;
        gf_boolean_t dir_ok         = _gf_false;
        char *pdir                  = NULL;
        char *t                     = NULL;

        GF_ASSERT (req);
        GF_ASSERT (this);

        ret = xdr_to_generic (req->msg[0], &umnt_req,
                              (xdrproc_t)xdr_gf1_cli_umount_req);
        if (ret < 0) {
                //failed to decode msg;
                req->rpc_err = GARBAGE_ARGS;
                rsp.op_ret = -1;
                goto out;
        }

        gf_log ("glusterd", GF_LOG_INFO, "Received umount req");

        if (dict_get_str (this->options, "mountbroker-root",
                          &mountbroker_root) != 0) {
                rsp.op_errno = ENOENT;
                goto out;
        }

        /* check if it is allowed to umount path */
        path = gf_strdup (umnt_req.path);
        if (!path) {
                rsp.op_errno = ENOMEM;
                goto out;
        }
        dir_ok = _gf_false;
        pdir = dirname (path);
        t = strtail (pdir, mountbroker_root);
        if (t && *t == '/') {
                t = strtail(++t, MB_HIVE);
                if (t && !*t)
                        dir_ok = _gf_true;
        }
        GF_FREE (path);
        if (!dir_ok) {
                rsp.op_errno = EACCES;
                goto out;
        }

        runinit (&runner);
        runner_add_args (&runner, "umount", umnt_req.path, NULL);
        if (umnt_req.lazy)
                runner_add_arg (&runner, "-l");
        rsp.op_ret = runner_run (&runner);
        if (rsp.op_ret == 0) {
                if (realpath (umnt_req.path, mntp))
                        rmdir (mntp);
                else {
                        rsp.op_ret = -1;
                        rsp.op_errno = errno;
                }
                if (unlink (umnt_req.path) != 0) {
                        rsp.op_ret = -1;
                        rsp.op_errno = errno;
                }
        }

 out:
        if (rsp.op_errno)
                rsp.op_ret = -1;

        glusterd_submit_reply (req, &rsp, NULL, 0, NULL,
                               (xdrproc_t)xdr_gf1_cli_umount_rsp);
        ret = 0;

        glusterd_friend_sm ();
        glusterd_op_sm ();

        return ret;
}

int32_t
glusterd_get_volumes (rpcsvc_request_t *req, dict_t *dict, int32_t flags)
{
        int32_t                 ret = -1;
        glusterd_conf_t         *priv = NULL;
        glusterd_volinfo_t      *entry = NULL;
        int32_t                 count = 0;
        dict_t                  *volumes = NULL;
        gf_cli_rsp              rsp = {0,};
        char                    *volname = NULL;

        priv = THIS->private;
        GF_ASSERT (priv);

        volumes = dict_new ();
        if (!volumes) {
                gf_log ("", GF_LOG_WARNING, "Out of Memory");
                goto out;
        }

        if (list_empty (&priv->volumes)) {
                ret = 0;
                goto respond;
        }

        if (flags == GF_CLI_GET_VOLUME_ALL) {
                list_for_each_entry (entry, &priv->volumes, vol_list) {
                        ret = glusterd_add_volume_detail_to_dict (entry,
                                                        volumes, count);
                        if (ret)
                                goto respond;

                        count++;

                }

        } else if (flags == GF_CLI_GET_NEXT_VOLUME) {
                ret = dict_get_str (dict, "volname", &volname);

                if (ret) {
                        if (priv->volumes.next) {
                                entry = list_entry (priv->volumes.next,
                                                    typeof (*entry),
                                                    vol_list);
                        }
                } else {
                        ret = glusterd_volinfo_find (volname, &entry);
                        if (ret)
                                goto respond;
                        entry = list_entry (entry->vol_list.next,
                                            typeof (*entry),
                                            vol_list);
                }

                if (&entry->vol_list == &priv->volumes) {
                       goto respond;
                } else {
                        ret = glusterd_add_volume_detail_to_dict (entry,
                                                         volumes, count);
                        if (ret)
                                goto respond;

                        count++;
                }
        } else if (flags == GF_CLI_GET_VOLUME) {
                ret = dict_get_str (dict, "volname", &volname);
                if (ret)
                        goto respond;

                ret = glusterd_volinfo_find (volname, &entry);
                if (ret)
                        goto respond;

                ret = glusterd_add_volume_detail_to_dict (entry,
                                                 volumes, count);
                if (ret)
                        goto respond;

                count++;
        }

respond:
        ret = dict_set_int32 (volumes, "count", count);
        if (ret)
                goto out;
        ret = dict_allocate_and_serialize (volumes, &rsp.dict.dict_val,
                                           &rsp.dict.dict_len);

        if (ret)
                goto out;

        ret = 0;
out:
        rsp.op_ret = ret;

        rsp.op_errstr = "";
        glusterd_submit_reply (req, &rsp, NULL, 0, NULL,
                               (xdrproc_t)xdr_gf_cli_rsp);
        ret = 0;

        if (volumes)
                dict_unref (volumes);

        GF_FREE (rsp.dict.dict_val);
        return ret;
}

int
glusterd_handle_status_volume (rpcsvc_request_t *req)
{
        int32_t                         ret     = -1;
        uint32_t                        cmd     = 0;
        dict_t                         *dict    = NULL;
        char                           *volname = 0;
        gf_cli_req                      cli_req = {{0,}};
        glusterd_op_t                   cli_op  = GD_OP_STATUS_VOLUME;
        char                            err_str[2048] = {0,};
        xlator_t                       *this = NULL;

        GF_ASSERT (req);
        this = THIS;
        GF_ASSERT (this);

        ret = xdr_to_generic (req->msg[0], &cli_req, (xdrproc_t)xdr_gf_cli_req);
        if (ret < 0) {
                //failed to decode msg;
                req->rpc_err = GARBAGE_ARGS;
                goto out;
        }

        if (cli_req.dict.dict_len > 0) {
                dict = dict_new();
                if (!dict)
                        goto out;
                ret = dict_unserialize (cli_req.dict.dict_val,
                                        cli_req.dict.dict_len, &dict);
                if (ret < 0) {
                        gf_log (this->name, GF_LOG_ERROR, "failed to "
                                "unserialize buffer");
                        snprintf (err_str, sizeof (err_str), "Unable to decode "
                                  "the command");
                        goto out;
                }

        }

        ret = dict_get_uint32 (dict, "cmd", &cmd);
        if (ret)
                goto out;

        if (!(cmd & GF_CLI_STATUS_ALL)) {
                ret = dict_get_str (dict, "volname", &volname);
                if (ret) {
                        snprintf (err_str, sizeof (err_str), "Unable to get "
                                  "volume name");
                        gf_log (this->name, GF_LOG_ERROR, "%s", err_str);
                        goto out;
                }
                gf_log (this->name, GF_LOG_INFO,
                        "Received status volume req for volume %s", volname);

        }

        ret = glusterd_op_begin_synctask (req, GD_OP_STATUS_VOLUME, dict);

out:

        if (ret) {
                if (err_str[0] == '\0')
                        snprintf (err_str, sizeof (err_str),
                                  "Operation failed");
                ret = glusterd_op_send_cli_response (cli_op, ret, 0, req,
                                                     dict, err_str);
        }
        free (cli_req.dict.dict_val);

        return ret;
}

int
glusterd_handle_cli_clearlocks_volume (rpcsvc_request_t *req)
{
        int32_t                         ret = -1;
        gf_cli_req                      cli_req = {{0,}};
        glusterd_op_t                   cli_op = GD_OP_CLEARLOCKS_VOLUME;
        char                            *volname = NULL;
        dict_t                          *dict = NULL;
        char                            err_str[2048] = {0,};
        xlator_t                        *this = NULL;

        GF_ASSERT (req);
        this = THIS;
        GF_ASSERT (this);

        ret = -1;
        ret = xdr_to_generic (req->msg[0], &cli_req, (xdrproc_t)xdr_gf_cli_req);
        if (ret < 0) {
                req->rpc_err = GARBAGE_ARGS;
                goto out;
        }

        if (cli_req.dict.dict_len) {
                dict  = dict_new ();

                ret = dict_unserialize (cli_req.dict.dict_val,
                                        cli_req.dict.dict_len,
                                        &dict);
                if (ret < 0) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "failed to unserialize req-buffer to"
                                " dictionary");
                        snprintf (err_str, sizeof (err_str), "unable to decode "
                                  "the command");
                        goto out;
                }

        } else {
                ret = -1;
                gf_log (this->name, GF_LOG_ERROR, "Empty cli request.");
                goto out;
        }

        ret = dict_get_str (dict, "volname", &volname);
        if (ret) {
                snprintf (err_str, sizeof (err_str), "Unable to get volume "
                          "name");
                gf_log (this->name, GF_LOG_ERROR, "%s", err_str);
                goto out;
        }

        gf_log (this->name, GF_LOG_INFO, "Received clear-locks volume req "
                "for volume %s", volname);

        ret = glusterd_op_begin_synctask (req, GD_OP_CLEARLOCKS_VOLUME, dict);

out:
        if (ret) {
                if (err_str[0] == '\0')
                        snprintf (err_str, sizeof (err_str),
                                  "Operation failed");
                ret = glusterd_op_send_cli_response (cli_op, ret, 0, req,
                                                     dict, err_str);
        }
        free (cli_req.dict.dict_val);

        return ret;
}

rpcsvc_actor_t gd_svc_cli_actors[] = {
        [GLUSTER_CLI_PROBE]         = { "CLI_PROBE", GLUSTER_CLI_PROBE, glusterd_handle_cli_probe, NULL, 0},
        [GLUSTER_CLI_CREATE_VOLUME] = { "CLI_CREATE_VOLUME", GLUSTER_CLI_CREATE_VOLUME, glusterd_handle_create_volume, NULL, 0},
        [GLUSTER_CLI_DEFRAG_VOLUME] = { "CLI_DEFRAG_VOLUME", GLUSTER_CLI_DEFRAG_VOLUME, glusterd_handle_defrag_volume, NULL, 0},
        [GLUSTER_CLI_DEPROBE]       = { "FRIEND_REMOVE", GLUSTER_CLI_DEPROBE, glusterd_handle_cli_deprobe, NULL, 0},
        [GLUSTER_CLI_LIST_FRIENDS]  = { "LIST_FRIENDS", GLUSTER_CLI_LIST_FRIENDS, glusterd_handle_cli_list_friends, NULL, 0},
        [GLUSTER_CLI_UUID_RESET]    = { "UUID_RESET", GLUSTER_CLI_UUID_RESET, glusterd_handle_cli_uuid_reset, NULL, 0},
        [GLUSTER_CLI_START_VOLUME]  = { "START_VOLUME", GLUSTER_CLI_START_VOLUME, glusterd_handle_cli_start_volume, NULL, 0},
        [GLUSTER_CLI_STOP_VOLUME]   = { "STOP_VOLUME", GLUSTER_CLI_STOP_VOLUME, glusterd_handle_cli_stop_volume, NULL, 0},
        [GLUSTER_CLI_DELETE_VOLUME] = { "DELETE_VOLUME", GLUSTER_CLI_DELETE_VOLUME, glusterd_handle_cli_delete_volume, NULL, 0},
        [GLUSTER_CLI_GET_VOLUME]    = { "GET_VOLUME", GLUSTER_CLI_GET_VOLUME, glusterd_handle_cli_get_volume, NULL, 0},
        [GLUSTER_CLI_ADD_BRICK]     = { "ADD_BRICK", GLUSTER_CLI_ADD_BRICK, glusterd_handle_add_brick, NULL, 0},
        [GLUSTER_CLI_REPLACE_BRICK] = { "REPLACE_BRICK", GLUSTER_CLI_REPLACE_BRICK, glusterd_handle_replace_brick, NULL, 0},
        [GLUSTER_CLI_REMOVE_BRICK]  = { "REMOVE_BRICK", GLUSTER_CLI_REMOVE_BRICK, glusterd_handle_remove_brick, NULL, 0},
        [GLUSTER_CLI_LOG_ROTATE]    = { "LOG FILENAME", GLUSTER_CLI_LOG_ROTATE, glusterd_handle_log_rotate, NULL, 0},
        [GLUSTER_CLI_SET_VOLUME]    = { "SET_VOLUME", GLUSTER_CLI_SET_VOLUME, glusterd_handle_set_volume, NULL, 0},
        [GLUSTER_CLI_SYNC_VOLUME]   = { "SYNC_VOLUME", GLUSTER_CLI_SYNC_VOLUME, glusterd_handle_sync_volume, NULL, 0},
        [GLUSTER_CLI_RESET_VOLUME]  = { "RESET_VOLUME", GLUSTER_CLI_RESET_VOLUME, glusterd_handle_reset_volume, NULL, 0},
        [GLUSTER_CLI_FSM_LOG]       = { "FSM_LOG", GLUSTER_CLI_FSM_LOG, glusterd_handle_fsm_log, NULL, 0},
        [GLUSTER_CLI_GSYNC_SET]     = { "GSYNC_SET", GLUSTER_CLI_GSYNC_SET, glusterd_handle_gsync_set, NULL, 0},
        [GLUSTER_CLI_PROFILE_VOLUME] = { "STATS_VOLUME", GLUSTER_CLI_PROFILE_VOLUME, glusterd_handle_cli_profile_volume, NULL, 0},
        [GLUSTER_CLI_QUOTA]         = { "QUOTA", GLUSTER_CLI_QUOTA, glusterd_handle_quota, NULL, 0},
        [GLUSTER_CLI_GETWD]         = { "GETWD", GLUSTER_CLI_GETWD, glusterd_handle_getwd, NULL, 1},
        [GLUSTER_CLI_STATUS_VOLUME]  = {"STATUS_VOLUME", GLUSTER_CLI_STATUS_VOLUME, glusterd_handle_status_volume, NULL, 0},
        [GLUSTER_CLI_MOUNT]         = { "MOUNT", GLUSTER_CLI_MOUNT, glusterd_handle_mount, NULL, 1},
        [GLUSTER_CLI_UMOUNT]        = { "UMOUNT", GLUSTER_CLI_UMOUNT, glusterd_handle_umount, NULL, 1},
        [GLUSTER_CLI_HEAL_VOLUME]  = { "HEAL_VOLUME", GLUSTER_CLI_HEAL_VOLUME, glusterd_handle_cli_heal_volume, NULL, 0},
        [GLUSTER_CLI_STATEDUMP_VOLUME] = {"STATEDUMP_VOLUME", GLUSTER_CLI_STATEDUMP_VOLUME, glusterd_handle_cli_statedump_volume, NULL, 0},
        [GLUSTER_CLI_LIST_VOLUME] = {"LIST_VOLUME", GLUSTER_CLI_LIST_VOLUME, glusterd_handle_cli_list_volume, NULL, 0},
        [GLUSTER_CLI_CLRLOCKS_VOLUME] = {"CLEARLOCKS_VOLUME", GLUSTER_CLI_CLRLOCKS_VOLUME, glusterd_handle_cli_clearlocks_volume, NULL, 0},
#ifdef HAVE_BD_XLATOR
        [GLUSTER_CLI_BD_OP]       = {"BD_OP", GLUSTER_CLI_BD_OP, glusterd_handle_cli_bd_op, NULL, 0},
#endif
};

struct rpcsvc_program gd_svc_cli_prog = {
        .progname  = "GlusterD svc cli",
        .prognum   = GLUSTER_CLI_PROGRAM,
        .progver   = GLUSTER_CLI_VERSION,
        .numactors = GLUSTER_CLI_MAXVALUE,
        .actors    = gd_svc_cli_actors,
	.synctask  = _gf_true,
};
