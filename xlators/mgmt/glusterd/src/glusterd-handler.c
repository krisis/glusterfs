/*
   Copyright (c) 2006-2012 Red Hat, Inc. <http://www.redhat.com>
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
#include "defaults.h"
#include "compat.h"
#include "compat-errno.h"
#include "statedump.h"
#include "run.h"
#include "glusterd-mem-types.h"
#include "glusterd.h"
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

#include "defaults.c"
#include "common-utils.h"

#include "globals.h"
#include "glusterd-syncop.h"

#ifdef HAVE_BD_XLATOR
#include <lvm2app.h>
#endif


int
glusterd_handle_cluster_lock (rpcsvc_request_t *req)
{
        gd1_mgmt_cluster_lock_req       lock_req = {{0},};
        int32_t                         ret = -1;
        glusterd_op_lock_ctx_t          *ctx = NULL;
        glusterd_peerinfo_t             *peerinfo = NULL;
        xlator_t                        *this = NULL;

        this = THIS;
        GF_ASSERT (this);
        GF_ASSERT (req);

        ret = xdr_to_generic (req->msg[0], &lock_req,
                              (xdrproc_t)xdr_gd1_mgmt_cluster_lock_req);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_ERROR, "Failed to decode lock "
                        "request received from peer");
                req->rpc_err = GARBAGE_ARGS;
                goto out;
        }

        gf_log (this->name, GF_LOG_DEBUG, "Received LOCK from uuid: %s",
                uuid_utoa (lock_req.uuid));

        if (glusterd_friend_find_by_uuid (lock_req.uuid, &peerinfo)) {
                gf_log (this->name, GF_LOG_WARNING, "%s doesn't "
                        "belong to the cluster. Ignoring request.",
                        uuid_utoa (lock_req.uuid));
                ret = -1;
                goto out;
        }

        ctx = GF_CALLOC (1, sizeof (*ctx), gf_gld_mt_op_lock_ctx_t);

        if (!ctx) {
                //respond here
                return -1;
        }

        uuid_copy (ctx->uuid, lock_req.uuid);
        ctx->req = req;

        ret = glusterd_op_sm_inject_event (GD_OP_EVENT_LOCK, ctx);

out:
        gf_log (this->name, GF_LOG_DEBUG, "Returning %d", ret);

        glusterd_friend_sm ();
        glusterd_op_sm ();

        return ret;
}

int
glusterd_req_ctx_create (rpcsvc_request_t *rpc_req,
                         glusterd_op_t op, uuid_t uuid,
                         char *buf_val, size_t buf_len,
                         gf_gld_mem_types_t mem_type,
                         glusterd_req_ctx_t **req_ctx_out)
{
        int                 ret     = -1;
        char                str[50] = {0,};
        glusterd_req_ctx_t *req_ctx = NULL;
        dict_t             *dict    = NULL;
        xlator_t           *this    = NULL;

        this = THIS;
        GF_ASSERT (this);

        uuid_unparse (uuid, str);
        gf_log (this->name, GF_LOG_DEBUG, "Received op from uuid %s", str);

        dict = dict_new ();
        if (!dict)
                goto out;

        req_ctx = GF_CALLOC (1, sizeof (*req_ctx), mem_type);
        if (!req_ctx) {
                goto out;
        }

        uuid_copy (req_ctx->uuid, uuid);
        req_ctx->op = op;
        ret = dict_unserialize (buf_val, buf_len, &dict);
        if (ret) {
                gf_log (this->name, GF_LOG_WARNING,
                        "failed to unserialize the dictionary");
                goto out;
        }

        req_ctx->dict = dict;
        req_ctx->req = rpc_req;
        *req_ctx_out = req_ctx;
        ret = 0;
out:
        if (ret) {
                if (dict)
                        dict_unref (dict);
                GF_FREE (req_ctx);
        }
        return ret;
}

int
glusterd_handle_stage_op (rpcsvc_request_t *req)
{
        int32_t                         ret = -1;
        glusterd_req_ctx_t              *req_ctx = NULL;
        gd1_mgmt_stage_op_req           op_req = {{0},};
        glusterd_peerinfo_t             *peerinfo = NULL;
        xlator_t                        *this = NULL;

        this = THIS;
        GF_ASSERT (this);
        GF_ASSERT (req);

        ret = xdr_to_generic (req->msg[0], &op_req,
                              (xdrproc_t)xdr_gd1_mgmt_stage_op_req);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_ERROR, "Failed to decode stage "
                        "request received from peer");
                req->rpc_err = GARBAGE_ARGS;
                goto out;
        }

        if (glusterd_friend_find_by_uuid (op_req.uuid, &peerinfo)) {
                gf_log (this->name, GF_LOG_WARNING, "%s doesn't "
                        "belong to the cluster. Ignoring request.",
                        uuid_utoa (op_req.uuid));
                ret = -1;
                goto out;
        }

        ret = glusterd_req_ctx_create (req, op_req.op, op_req.uuid,
                                       op_req.buf.buf_val, op_req.buf.buf_len,
                                       gf_gld_mt_op_stage_ctx_t, &req_ctx);
        if (ret)
                goto out;

        ret = glusterd_op_sm_inject_event (GD_OP_EVENT_STAGE_OP, req_ctx);

 out:
        free (op_req.buf.buf_val);//malloced by xdr
        glusterd_friend_sm ();
        glusterd_op_sm ();
        return ret;
}

int
glusterd_handle_commit_op (rpcsvc_request_t *req)
{
        int32_t                         ret = -1;
        glusterd_req_ctx_t              *req_ctx = NULL;
        gd1_mgmt_commit_op_req          op_req = {{0},};
        glusterd_peerinfo_t             *peerinfo = NULL;
        xlator_t                        *this = NULL;

        this = THIS;
        GF_ASSERT (this);
        GF_ASSERT (req);

        ret = xdr_to_generic (req->msg[0], &op_req,
                              (xdrproc_t)xdr_gd1_mgmt_commit_op_req);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_ERROR, "Failed to decode commit "
                        "request received from peer");
                req->rpc_err = GARBAGE_ARGS;
                goto out;
        }

        if (glusterd_friend_find_by_uuid (op_req.uuid, &peerinfo)) {
                gf_log (this->name, GF_LOG_WARNING, "%s doesn't "
                        "belong to the cluster. Ignoring request.",
                        uuid_utoa (op_req.uuid));
                ret = -1;
                goto out;
        }

        //the structures should always be equal
        GF_ASSERT (sizeof (gd1_mgmt_commit_op_req) == sizeof (gd1_mgmt_stage_op_req));
        ret = glusterd_req_ctx_create (req, op_req.op, op_req.uuid,
                                       op_req.buf.buf_val, op_req.buf.buf_len,
                                       gf_gld_mt_op_commit_ctx_t, &req_ctx);
        if (ret)
                goto out;

        ret = glusterd_op_init_ctx (op_req.op);
        if (ret)
                goto out;

        ret = glusterd_op_sm_inject_event (GD_OP_EVENT_COMMIT_OP, req_ctx);

out:
        free (op_req.buf.buf_val);//malloced by xdr
        glusterd_friend_sm ();
        glusterd_op_sm ();
        return ret;
}

int
glusterd_op_lock_send_resp (rpcsvc_request_t *req, int32_t status)
{

        gd1_mgmt_cluster_lock_rsp       rsp = {{0},};
        int                             ret = -1;

        GF_ASSERT (req);
        glusterd_get_uuid (&rsp.uuid);
        rsp.op_ret = status;

        ret = glusterd_submit_reply (req, &rsp, NULL, 0, NULL,
                                     (xdrproc_t)xdr_gd1_mgmt_cluster_lock_rsp);

        gf_log (THIS->name, GF_LOG_DEBUG, "Responded to lock, ret: %d", ret);

        return 0;
}

int
glusterd_op_unlock_send_resp (rpcsvc_request_t *req, int32_t status)
{

        gd1_mgmt_cluster_unlock_rsp     rsp = {{0},};
        int                             ret = -1;

        GF_ASSERT (req);
        rsp.op_ret = status;
        glusterd_get_uuid (&rsp.uuid);

        ret = glusterd_submit_reply (req, &rsp, NULL, 0, NULL,
                                     (xdrproc_t)xdr_gd1_mgmt_cluster_unlock_rsp);

        gf_log (THIS->name, GF_LOG_DEBUG, "Responded to unlock, ret: %d", ret);

        return ret;
}

int
glusterd_handle_cluster_unlock (rpcsvc_request_t *req)
{
        gd1_mgmt_cluster_unlock_req     unlock_req = {{0}, };
        int32_t                         ret = -1;
        glusterd_op_lock_ctx_t          *ctx = NULL;
        glusterd_peerinfo_t             *peerinfo = NULL;
        xlator_t                        *this = NULL;

        this = THIS;
        GF_ASSERT (this);
        GF_ASSERT (req);

        ret = xdr_to_generic (req->msg[0], &unlock_req,
                              (xdrproc_t)xdr_gd1_mgmt_cluster_unlock_req);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_ERROR, "Failed to decode unlock "
                        "request received from peer");
                req->rpc_err = GARBAGE_ARGS;
                goto out;
        }


        gf_log (this->name, GF_LOG_DEBUG,
                "Received UNLOCK from uuid: %s", uuid_utoa (unlock_req.uuid));

        if (glusterd_friend_find_by_uuid (unlock_req.uuid, &peerinfo)) {
                gf_log (this->name, GF_LOG_WARNING, "%s doesn't "
                        "belong to the cluster. Ignoring request.",
                        uuid_utoa (unlock_req.uuid));
                ret = -1;
                goto out;
        }

        ctx = GF_CALLOC (1, sizeof (*ctx), gf_gld_mt_op_lock_ctx_t);

        if (!ctx) {
                //respond here
                return -1;
        }
        uuid_copy (ctx->uuid, unlock_req.uuid);
        ctx->req = req;

        ret = glusterd_op_sm_inject_event (GD_OP_EVENT_UNLOCK, ctx);

out:
        glusterd_friend_sm ();
        glusterd_op_sm ();

        return ret;
}

int
glusterd_op_stage_send_resp (rpcsvc_request_t   *req,
                             int32_t op, int32_t status,
                             char *op_errstr, dict_t *rsp_dict)
{
        gd1_mgmt_stage_op_rsp           rsp      = {{0},};
        int                             ret      = -1;
        xlator_t                       *this     = NULL;

        this = THIS;
        GF_ASSERT (this);
        GF_ASSERT (req);

        rsp.op_ret = status;
        glusterd_get_uuid (&rsp.uuid);
        rsp.op = op;
        if (op_errstr)
                rsp.op_errstr = op_errstr;
        else
                rsp.op_errstr = "";

        ret = dict_allocate_and_serialize (rsp_dict, &rsp.dict.dict_val,
                                           &rsp.dict.dict_len);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_ERROR,
                        "failed to get serialized length of dict");
                return ret;
        }

        ret = glusterd_submit_reply (req, &rsp, NULL, 0, NULL,
                                     (xdrproc_t)xdr_gd1_mgmt_stage_op_rsp);

        gf_log (this->name, GF_LOG_DEBUG, "Responded to stage, ret: %d", ret);
        GF_FREE (rsp.dict.dict_val);

        return ret;
}

int
glusterd_op_commit_send_resp (rpcsvc_request_t *req,
                               int32_t op, int32_t status, char *op_errstr,
                               dict_t *rsp_dict)
{
        gd1_mgmt_commit_op_rsp          rsp      = {{0}, };
        int                             ret      = -1;
        xlator_t                        *this = NULL;

        this = THIS;
        GF_ASSERT (this);
        GF_ASSERT (req);
        rsp.op_ret = status;
        glusterd_get_uuid (&rsp.uuid);
        rsp.op = op;

        if (op_errstr)
                rsp.op_errstr = op_errstr;
        else
                rsp.op_errstr = "";

        if (rsp_dict) {
                ret = dict_allocate_and_serialize (rsp_dict, &rsp.dict.dict_val,
                                                   &rsp.dict.dict_len);
                if (ret < 0) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "failed to get serialized length of dict");
                        goto out;
                }
        }


        ret = glusterd_submit_reply (req, &rsp, NULL, 0, NULL,
                                     (xdrproc_t)xdr_gd1_mgmt_commit_op_rsp);

        gf_log (this->name, GF_LOG_DEBUG, "Responded to commit, ret: %d", ret);

out:
        GF_FREE (rsp.dict.dict_val);
        return ret;
}


int
glusterd_brick_rpc_notify (struct rpc_clnt *rpc, void *mydata,
                          rpc_clnt_event_t event,
                          void *data)
{
        xlator_t                *this = NULL;
        glusterd_conf_t         *conf = NULL;
        int                     ret = 0;
        glusterd_brickinfo_t    *brickinfo = NULL;

        brickinfo = mydata;
        if (!brickinfo)
                return 0;

        this = THIS;
        GF_ASSERT (this);
        conf = this->private;
        GF_ASSERT (conf);

        switch (event) {
        case RPC_CLNT_CONNECT:
                gf_log (this->name, GF_LOG_DEBUG, "got RPC_CLNT_CONNECT");
                glusterd_set_brick_status (brickinfo, GF_BRICK_STARTED);
                ret = default_notify (this, GF_EVENT_CHILD_UP, NULL);

                break;

        case RPC_CLNT_DISCONNECT:
                gf_log (this->name, GF_LOG_DEBUG, "got RPC_CLNT_DISCONNECT");
                glusterd_set_brick_status (brickinfo, GF_BRICK_STOPPED);
                break;

        default:
                gf_log (this->name, GF_LOG_TRACE,
                        "got some other RPC event %d", event);
                break;
        }

        return ret;
}

int
glusterd_nodesvc_rpc_notify (struct rpc_clnt *rpc, void *mydata,
                             rpc_clnt_event_t event,
                             void *data)
{
        xlator_t                *this = NULL;
        glusterd_conf_t         *conf = NULL;
        char                    *server = NULL;
        int                     ret = 0;

        this = THIS;
        GF_ASSERT (this);
        conf = this->private;
        GF_ASSERT (conf);

        server = mydata;
        if (!server)
                return 0;

        switch (event) {
        case RPC_CLNT_CONNECT:
                gf_log (this->name, GF_LOG_DEBUG, "got RPC_CLNT_CONNECT");
                (void) glusterd_nodesvc_set_online_status (server, _gf_true);
                ret = default_notify (this, GF_EVENT_CHILD_UP, NULL);

                break;

        case RPC_CLNT_DISCONNECT:
                gf_log (this->name, GF_LOG_DEBUG, "got RPC_CLNT_DISCONNECT");
                (void) glusterd_nodesvc_set_online_status (server, _gf_false);
                break;

        default:
                gf_log (this->name, GF_LOG_TRACE,
                        "got some other RPC event %d", event);
                break;
        }

        return ret;
}

int
glusterd_null (rpcsvc_request_t *req)
{

        return 0;
}

rpcsvc_actor_t gd_svc_mgmt_actors[] = {
        [GLUSTERD_MGMT_NULL]           = { "NULL", GLUSTERD_MGMT_NULL, glusterd_null, NULL, 0},
        [GLUSTERD_MGMT_CLUSTER_LOCK]   = { "CLUSTER_LOCK", GLUSTERD_MGMT_CLUSTER_LOCK, glusterd_handle_cluster_lock, NULL, 0},
        [GLUSTERD_MGMT_CLUSTER_UNLOCK] = { "CLUSTER_UNLOCK", GLUSTERD_MGMT_CLUSTER_UNLOCK, glusterd_handle_cluster_unlock, NULL, 0},
        [GLUSTERD_MGMT_STAGE_OP]       = { "STAGE_OP", GLUSTERD_MGMT_STAGE_OP, glusterd_handle_stage_op, NULL, 0},
        [GLUSTERD_MGMT_COMMIT_OP]      = { "COMMIT_OP", GLUSTERD_MGMT_COMMIT_OP, glusterd_handle_commit_op, NULL, 0},
};

struct rpcsvc_program gd_svc_mgmt_prog = {
        .progname  = "GlusterD svc mgmt",
        .prognum   = GD_MGMT_PROGRAM,
        .progver   = GD_MGMT_VERSION,
        .numactors = GLUSTERD_MGMT_MAXVALUE,
        .actors    = gd_svc_mgmt_actors,
	.synctask  = _gf_true,
};
