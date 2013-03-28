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

#include "rpc-clnt.h"
#include "glusterd1-xdr.h"
#include "cli1-xdr.h"

#include "xdr-generic.h"

#include "compat-errno.h"
#include "glusterd-sm.h"
#include "glusterd.h"
#include "protocol-common.h"
#include "glusterd-utils.h"
#include "common-utils.h"
#include <sys/uio.h>


int
glusterd_probe_cbk (struct rpc_req *req, struct iovec *iov,
                    int count, void *myframe)
{
        gd1_mgmt_probe_rsp            rsp           = {{0},};
        glusterd_peerinfo_t           *peerinfo     = NULL;
        glusterd_friend_sm_event_t    *event        = NULL;
        glusterd_probe_ctx_t          *ctx          = NULL;
        call_frame_t                  *frame        = NULL;
        gf_boolean_t                  probe_failed  = _gf_false;
        xlator_t                      *this         = NULL;
        int                           ret           = 0;

        this = THIS;
        if (-1 == req->rpc_status)
                goto out;

        ret = xdr_to_generic (*iov, &rsp, (xdrproc_t)xdr_gd1_mgmt_probe_rsp);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_ERROR, "Failed to decode probe "
                        "response");
                rsp.op_ret   = -1;
                rsp.op_errno = EINVAL;
                goto out;
        }

        gf_log (this->name, GF_LOG_INFO, "Received probe response from "
                "uuid: %s, host: %s", uuid_utoa (rsp.uuid), rsp.hostname);

        frame = myframe;
        ctx   = frame->local;
        GF_ASSERT (ctx);
        frame->local = NULL;

        if (rsp.op_ret != 0) {
                ret = rsp.op_ret;
                probe_failed = _gf_true;
                goto out;
        }
        ret = glusterd_friend_find (rsp.uuid, rsp.hostname, &peerinfo);
        if (ret) {
                GF_ASSERT (0);
        }

        if (strncasecmp (rsp.hostname, peerinfo->hostname, 1024)) {
                gf_log (THIS->name, GF_LOG_INFO, "Host: %s  with uuid: %s "
                        "already present in cluster with alias hostname: %s",
                        rsp.hostname, uuid_utoa (rsp.uuid), peerinfo->hostname);
                /* For glusterd_friend_find to lookup for this peerinfo entry
                 * based on hostname (and not based on uuid).
                 * See git show 3672c989 for more context
                 */
                uuid_copy (rsp.uuid, (uuid_t){0});
                ret = rsp.op_ret;
                probe_failed = _gf_true;
                goto out;
        }

        uuid_copy (peerinfo->uuid, rsp.uuid);
        ret = glusterd_friend_sm_new_event
                        (GD_FRIEND_EVENT_INIT_FRIEND_REQ, &event);
        if (ret) {
                gf_log ("glusterd", GF_LOG_ERROR, "Unable to get event");
                goto out;
        }

        event->peerinfo = peerinfo;
        event->ctx      = ctx;
        ret = glusterd_friend_sm_inject_event (event);
        if (!ret)
                glusterd_friend_sm ();

out:
        if (probe_failed) {
                if (ctx->req) {
                        glusterd_xfer_cli_probe_resp (ctx->req, rsp.op_ret,
                                                      rsp.op_errno,
                                                      rsp.op_errstr,
                                                      ctx->hostname, ctx->port);
                }
                glusterd_destroy_probe_ctx (ctx);
                (void) glusterd_friend_remove (rsp.uuid, rsp.hostname);
        }
        free (rsp.hostname);//malloced by xdr
        GLUSTERD_STACK_DESTROY (frame);
        return ret;
}


int
glusterd_friend_add_cbk (struct rpc_req * req, struct iovec *iov,
                         int count, void *myframe)
{
        call_frame_t                        *frame      = NULL;
        gd1_mgmt_friend_rsp                 rsp         = {{0},};
        glusterd_friend_sm_event_t          *event      = NULL;
        glusterd_friend_sm_event_type_t     event_type  = GD_FRIEND_EVENT_NONE;
        glusterd_peerinfo_t                 *peerinfo   = NULL;
        glusterd_probe_ctx_t                *ctx        = NULL;
        glusterd_friend_update_ctx_t        *ev_ctx     = NULL;
        int32_t                             op_ret      = -1;
        int32_t                             op_errno    = -1;
        int                                 ret         = -1;

        if (-1 == req->rpc_status) {
                rsp.op_ret   = -1;
                rsp.op_errno = EINVAL;
                goto out;
        }

        ret = xdr_to_generic (*iov, &rsp, (xdrproc_t)xdr_gd1_mgmt_friend_rsp);
        if (ret < 0) {
                gf_log ("", GF_LOG_ERROR, "error");
                rsp.op_ret   = -1;
                rsp.op_errno = EINVAL;
                goto out;
        }

        op_ret = rsp.op_ret;
        op_errno = rsp.op_errno;

        gf_log ("glusterd", GF_LOG_INFO, "Received %s from uuid: %s, host: %s,"
                " port: %d", (op_ret)?"RJT":"ACC", uuid_utoa (rsp.uuid),
                rsp.hostname, rsp.port);

        ret = glusterd_friend_find (rsp.uuid, rsp.hostname, &peerinfo);
        if (ret) {
                gf_log ("", GF_LOG_ERROR, "received friend add response from"
                        " unknown peer uuid: %s", uuid_utoa (rsp.uuid));
                goto out;
        }

        if (op_ret)
                event_type = GD_FRIEND_EVENT_RCVD_RJT;
        else
                event_type = GD_FRIEND_EVENT_RCVD_ACC;

        ret = glusterd_friend_sm_new_event (event_type, &event);
        if (ret) {
                gf_log ("glusterd", GF_LOG_ERROR, "Unable to get event");
                goto out;
        }
        event->peerinfo = peerinfo;
        ev_ctx = GF_CALLOC (1, sizeof (*ev_ctx), gf_gld_mt_friend_update_ctx_t);
        if (!ev_ctx) {
                ret = -1;
                goto out;
        }

        uuid_copy (ev_ctx->uuid, rsp.uuid);
        ev_ctx->hostname = gf_strdup (rsp.hostname);

        event->ctx = ev_ctx;
        ret = glusterd_friend_sm_inject_event (event);
        if (ret)
                goto out;

out:
        frame = myframe;
        ctx = frame->local;
        GF_ASSERT (ctx);
        frame->local = NULL;

        if (ctx->req)//reverse probe doesn't have req
                ret = glusterd_xfer_cli_probe_resp (ctx->req, op_ret, op_errno,
                                                    NULL, ctx->hostname,
                                                    ctx->port);
        if (ctx)
                glusterd_destroy_probe_ctx (ctx);

        if (!ret)
                glusterd_friend_sm ();
        free (rsp.hostname);//malloced by xdr
        GLUSTERD_STACK_DESTROY (frame);
        return ret;
}


int
glusterd_friend_remove_cbk (struct rpc_req * req, struct iovec *iov,
                            int count, void *myframe)
{
        call_frame_t                    *frame      = NULL;
        gd1_mgmt_friend_rsp             rsp         = {{0},};
        glusterd_conf_t                 *conf       = NULL;
        glusterd_friend_sm_event_t      *event      = NULL;
        glusterd_friend_sm_event_type_t event_type  = GD_FRIEND_EVENT_NONE;
        glusterd_peerinfo_t             *peerinfo   = NULL;
        glusterd_probe_ctx_t            *ctx        = NULL;
        gf_boolean_t                    move_sm_now = _gf_true;
        int32_t                         op_ret      = -1;
        int32_t                         op_errno    = -1;
        int                             ret         = -1;

        conf  = THIS->private;
        GF_ASSERT (conf);

        frame = myframe;
        ctx = frame->local;
        frame->local = NULL;
        GF_ASSERT (ctx);

        if (-1 == req->rpc_status) {
                rsp.op_ret   = -1;
                rsp.op_errno = EINVAL;
                move_sm_now = _gf_false;
                goto inject;
        }

        ret = xdr_to_generic (*iov, &rsp, (xdrproc_t)xdr_gd1_mgmt_friend_rsp);
        if (ret < 0) {
                gf_log ("", GF_LOG_ERROR, "error");
                rsp.op_ret   = -1;
                rsp.op_errno = EINVAL;
                goto respond;
        }

        op_ret = rsp.op_ret;
        op_errno = rsp.op_errno;

        gf_log ("glusterd", GF_LOG_INFO, "Received %s from uuid: %s, host: %s, "
                "port: %d", (op_ret)?"RJT":"ACC", uuid_utoa (rsp.uuid),
                rsp.hostname, rsp.port);

inject:
        ret = glusterd_friend_find (rsp.uuid, ctx->hostname, &peerinfo);
        if (ret) {
                /*Can happen as part of rpc clnt connection cleanup
                 *when the frame times out after 30 minutes */
                goto respond;
        }

        event_type = GD_FRIEND_EVENT_REMOVE_FRIEND;
        ret = glusterd_friend_sm_new_event (event_type, &event);
        if (ret) {
                gf_log ("glusterd", GF_LOG_ERROR, "Unable to get event");
                goto respond;
        }
        event->peerinfo = peerinfo;
        ret = glusterd_friend_sm_inject_event (event);
        if (ret)
                goto respond;

        /*friend_sm would be moved on CLNT_DISCONNECT, consequently
          cleaning up peerinfo. Else, we run the risk of triggering
          a clnt_destroy within saved_frames_unwind.
        */
        op_ret = 0;

respond:
        ret = glusterd_xfer_cli_deprobe_resp (ctx->req, op_ret, op_errno, NULL,
                                              ctx->hostname);
        if (!ret && move_sm_now) {
                glusterd_friend_sm ();
        }

        if (ctx) {
                glusterd_broadcast_friend_delete (ctx->hostname, NULL);
                glusterd_destroy_probe_ctx (ctx);
        }
        free (rsp.hostname);//malloced by xdr
        GLUSTERD_STACK_DESTROY (frame);
        return ret;
}


int32_t
glusterd_friend_update_cbk (struct rpc_req *req, struct iovec *iov,
                              int count, void *myframe)
{
        int                           ret    = -1;
        gd1_mgmt_friend_update_rsp    rsp    = {{0}, };
        xlator_t                      *this  = NULL;

        GF_ASSERT (req);
        this = THIS;

        if (-1 == req->rpc_status) {
                gf_log (this->name, GF_LOG_ERROR, "RPC Error");
                goto out;
        }

        ret = xdr_to_generic (*iov, &rsp,
                              (xdrproc_t)xdr_gd1_mgmt_friend_update_rsp);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_ERROR, "Failed to serialize friend"
                        " update repsonse");
                goto out;
        }

        ret = 0;
out:
        gf_log (this->name, GF_LOG_INFO, "Received %s from uuid: %s",
                (ret)?"RJT":"ACC", uuid_utoa (rsp.uuid));

        GLUSTERD_STACK_DESTROY (((call_frame_t *)myframe));
        return ret;
}


int32_t
glusterd_rpc_probe (call_frame_t *frame, xlator_t *this,
                    void *data)
{
        gd1_mgmt_probe_req      req = {{0},};
        int                     ret = 0;
        int                     port = 0;
        char                    *hostname = NULL;
        glusterd_peerinfo_t     *peerinfo = NULL;
        glusterd_conf_t         *priv = NULL;
        dict_t                  *dict = NULL;

        if (!frame || !this ||  !data) {
                ret = -1;
                goto out;
        }

        dict = data;
        priv = this->private;

        GF_ASSERT (priv);
        ret = dict_get_str (dict, "hostname", &hostname);
        if (ret)
                goto out;
        ret = dict_get_int32 (dict, "port", &port);
        if (ret)
                port = GF_DEFAULT_BASE_PORT;

        ret = dict_get_ptr (dict, "peerinfo", VOID (&peerinfo));
        if (ret)
                goto out;

        uuid_copy (req.uuid, MY_UUID);
        req.hostname = gf_strdup (hostname);
        req.port = port;

        ret = glusterd_submit_request (peerinfo->rpc, &req, frame, peerinfo->peer,
                                       GLUSTERD_PROBE_QUERY,
                                       NULL, this, glusterd_probe_cbk,
                                       (xdrproc_t)xdr_gd1_mgmt_probe_req);

out:
        GF_FREE (req.hostname);
        gf_log ("glusterd", GF_LOG_DEBUG, "Returning %d", ret);
        return ret;
}


int32_t
glusterd_rpc_friend_add (call_frame_t *frame, xlator_t *this,
                         void *data)
{
        gd1_mgmt_friend_req         req      = {{0},};
        int                         ret      = 0;
        glusterd_peerinfo_t        *peerinfo = NULL;
        glusterd_conf_t            *priv     = NULL;
        glusterd_friend_sm_event_t *event    = NULL;
        dict_t                     *vols     = NULL;


        if (!frame || !this || !data) {
                ret = -1;
                goto out;
        }

        event = data;
        priv = this->private;

        GF_ASSERT (priv);

        peerinfo = event->peerinfo;

        ret = glusterd_build_volume_dict (&vols);
        if (ret)
                goto out;

        uuid_copy (req.uuid, MY_UUID);
        req.hostname = peerinfo->hostname;
        req.port = peerinfo->port;

        ret = dict_allocate_and_serialize (vols, &req.vols.vols_val,
                                           &req.vols.vols_len);
        if (ret)
                goto out;

        ret = glusterd_submit_request (peerinfo->rpc, &req, frame, peerinfo->peer,
                                       GLUSTERD_FRIEND_ADD,
                                       NULL, this, glusterd_friend_add_cbk,
                                       (xdrproc_t)xdr_gd1_mgmt_friend_req);


out:
        GF_FREE (req.vols.vols_val);

        if (vols)
                dict_unref (vols);

        gf_log ("glusterd", GF_LOG_DEBUG, "Returning %d", ret);
        return ret;
}


int32_t
glusterd_rpc_friend_remove (call_frame_t *frame, xlator_t *this,
                            void *data)
{
        gd1_mgmt_friend_req             req = {{0},};
        int                             ret = 0;
        glusterd_peerinfo_t             *peerinfo = NULL;
        glusterd_conf_t                 *priv = NULL;
        glusterd_friend_sm_event_t      *event = NULL;

        if (!frame || !this || !data) {
                ret = -1;
                goto out;
        }

        event = data;
        priv = this->private;

        GF_ASSERT (priv);

        peerinfo = event->peerinfo;

        uuid_copy (req.uuid, MY_UUID);
        req.hostname = peerinfo->hostname;
        req.port = peerinfo->port;
        ret = glusterd_submit_request (peerinfo->rpc, &req, frame, peerinfo->peer,
                                       GLUSTERD_FRIEND_REMOVE, NULL,
                                       this, glusterd_friend_remove_cbk,
                                       (xdrproc_t)xdr_gd1_mgmt_friend_req);

out:
        gf_log ("glusterd", GF_LOG_DEBUG, "Returning %d", ret);
        return ret;
}


int32_t
glusterd_rpc_friend_update (call_frame_t *frame, xlator_t *this,
                            void *data)
{
        gd1_mgmt_friend_update  req         = {{0},};
        int                     ret         = 0;
        glusterd_conf_t        *priv        = NULL;
        dict_t                 *friends     = NULL;
        call_frame_t           *dummy_frame = NULL;
        glusterd_peerinfo_t    *peerinfo    = NULL;

        priv = this->private;
        GF_ASSERT (priv);

        friends = data;
        if (!friends)
                goto out;

        ret = dict_get_ptr (friends, "peerinfo", VOID(&peerinfo));
        if (ret)
                goto out;

        ret = dict_allocate_and_serialize (friends, &req.friends.friends_val,
                                           &req.friends.friends_len);
        if (ret)
                goto out;

        uuid_copy (req.uuid, MY_UUID);

        dummy_frame = create_frame (this, this->ctx->pool);
        ret = glusterd_submit_request (peerinfo->rpc, &req, dummy_frame,
                                       peerinfo->peer,
                                       GLUSTERD_FRIEND_UPDATE, NULL,
                                       this, glusterd_friend_update_cbk,
                                       (xdrproc_t)xdr_gd1_mgmt_friend_update);

out:
        GF_FREE (req.friends.friends_val);

        gf_log ("glusterd", GF_LOG_DEBUG, "Returning %d", ret);
        return ret;
}

struct rpc_clnt_procedure gd_peer_actors[GLUSTERD_FRIEND_MAXVALUE] = {
        [GLUSTERD_FRIEND_NULL]   = {"NULL", NULL },
        [GLUSTERD_PROBE_QUERY]   = {"PROBE_QUERY", glusterd_rpc_probe},
        [GLUSTERD_FRIEND_ADD]    = {"FRIEND_ADD", glusterd_rpc_friend_add},
        [GLUSTERD_FRIEND_REMOVE] = {"FRIEND_REMOVE", glusterd_rpc_friend_remove},
        [GLUSTERD_FRIEND_UPDATE] = {"FRIEND_UPDATE", glusterd_rpc_friend_update},
};

struct rpc_clnt_program gd_peer_prog = {
        .progname  = "Peer mgmt",
        .prognum   = GD_FRIEND_PROGRAM,
        .progver   = GD_FRIEND_VERSION,
        .proctable = gd_peer_actors,
        .numproc   = GLUSTERD_FRIEND_MAXVALUE,
};
