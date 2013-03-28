/*
   Copyright (c) 2010-2012 Red Hat, Inc. <http://www.redhat.com>
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
#include "glusterd-op-sm.h"
#include "glusterd-sm.h"
#include "glusterd.h"
#include "protocol-common.h"
#include "glusterd-utils.h"
#include "common-utils.h"
#include <sys/uio.h>


#define SERVER_PATH_MAX  (16 * 1024)


extern glusterd_op_info_t opinfo;

int32_t
glusterd_op_send_cli_response (glusterd_op_t op, int32_t op_ret,
                               int32_t op_errno, rpcsvc_request_t *req,
                               void *op_ctx, char *op_errstr)
{
        int32_t         ret = -1;
        void            *cli_rsp = NULL;
        dict_t          *ctx = NULL;
        char            *free_ptr = NULL;
        glusterd_conf_t *conf = NULL;
        xdrproc_t       xdrproc = NULL;
        char            *errstr = NULL;
        int32_t         status = 0;
        int32_t         count = 0;
        gf_cli_rsp      rsp = {0,};
        xlator_t        *this = NULL;

        this = THIS;
        GF_ASSERT (this);
        conf = this->private;

        GF_ASSERT (conf);

        ctx = op_ctx;

        switch (op) {
        case GD_OP_REMOVE_BRICK:
        {
                if (ctx)
                        ret = dict_get_str (ctx, "errstr", &errstr);
                break;
        }
        case GD_OP_RESET_VOLUME:
        {
                if (op_ret && !op_errstr)
                        errstr = "Error while resetting options";
                break;
        }
        case GD_OP_REBALANCE:
        case GD_OP_DEFRAG_BRICK_VOLUME:
        {
                if (ctx) {
                        ret = dict_get_int32 (ctx, "status", &status);
                        if (ret) {
                                gf_log (this->name, GF_LOG_TRACE,
                                        "failed to get status");
                        }
                }
                break;
        }
        case GD_OP_GSYNC_SET:
        {
               if (ctx) {
                        ret = dict_get_str (ctx, "errstr", &errstr);
                        ret = dict_set_str (ctx, "glusterd_workdir", conf->workdir);
                        /* swallow error here, that will be re-triggered in cli */

               }
               break;

        }
        case GD_OP_QUOTA:
        {
                if (ctx && !op_errstr) {
                        ret = dict_get_str (ctx, "errstr", &errstr);
                }
                break;
        }
        case GD_OP_PROFILE_VOLUME:
        {
                if (ctx && dict_get_int32 (ctx, "count", &count)) {
                        ret = dict_set_int32 (ctx, "count", 0);
                        if (ret) {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "failed to set count in dictionary");
                        }
                }
                break;
        }
        case GD_OP_START_BRICK:
        case GD_OP_STOP_BRICK:
        {
                gf_log (this->name, GF_LOG_DEBUG, "op '%s' not supported",
                        gd_op_list[op]);
                break;
        }
        case GD_OP_NONE:
        case GD_OP_MAX:
        {
                gf_log (this->name, GF_LOG_ERROR, "invalid operation");
                break;
        }
        case GD_OP_CREATE_VOLUME:
        case GD_OP_START_VOLUME:
        case GD_OP_STOP_VOLUME:
        case GD_OP_DELETE_VOLUME:
        case GD_OP_DEFRAG_VOLUME:
        case GD_OP_ADD_BRICK:
        case GD_OP_LOG_ROTATE:
        case GD_OP_SYNC_VOLUME:
        case GD_OP_STATEDUMP_VOLUME:
        case GD_OP_REPLACE_BRICK:
        case GD_OP_STATUS_VOLUME:
        case GD_OP_SET_VOLUME:
        case GD_OP_LIST_VOLUME:
        case GD_OP_CLEARLOCKS_VOLUME:
        case GD_OP_HEAL_VOLUME:
        case GD_OP_BD_OP:
        {
                /*nothing specific to be done*/
                break;
        }
        }

        rsp.op_ret = op_ret;
        rsp.op_errno = errno;
        if (errstr)
                rsp.op_errstr = errstr;
        else if (op_errstr)
                rsp.op_errstr = op_errstr;

        if (!rsp.op_errstr)
                rsp.op_errstr = "";

        if (ctx) {
                ret = dict_allocate_and_serialize (ctx, &rsp.dict.dict_val,
                                                   &rsp.dict.dict_len);
                if (ret < 0 )
                        gf_log (this->name, GF_LOG_ERROR, "failed to "
                                "serialize buffer");
                else
                        free_ptr = rsp.dict.dict_val;
        }

        /* needed by 'rebalance status' */
        if (status)
                rsp.op_errno = status;

        cli_rsp = &rsp;
        xdrproc = (xdrproc_t) xdr_gf_cli_rsp;

        glusterd_to_cli (req, cli_rsp, NULL, 0, NULL,
                         xdrproc, ctx);
        ret = 0;

        GF_FREE (free_ptr);
        gf_log (this->name, GF_LOG_DEBUG, "Returning %d", ret);
        return ret;
}

int32_t
glusterd_cluster_lock_cbk (struct rpc_req *req, struct iovec *iov,
                              int count, void *myframe)
{
        gd1_mgmt_cluster_lock_rsp     rsp   = {{0},};
        int                           ret   = -1;
        int32_t                       op_ret = -1;
        glusterd_op_sm_event_type_t   event_type = GD_OP_EVENT_NONE;
        glusterd_peerinfo_t           *peerinfo = NULL;
        xlator_t                      *this = NULL;

        this = THIS;
        GF_ASSERT (this);
        GF_ASSERT (req);

        if (-1 == req->rpc_status) {
                rsp.op_ret   = -1;
                rsp.op_errno = EINVAL;
                goto out;
        }

        ret = xdr_to_generic (*iov, &rsp, (xdrproc_t)xdr_gd1_mgmt_cluster_lock_rsp);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_ERROR, "Failed to decode lock "
                        "response received from peer");
                rsp.op_ret   = -1;
                rsp.op_errno = EINVAL;
                goto out;
        }

out:
        op_ret = rsp.op_ret;

        gf_log (this->name, (op_ret) ? GF_LOG_ERROR : GF_LOG_DEBUG,
                "Received lock %s from uuid: %s", (op_ret) ? "RJT" : "ACC",
                uuid_utoa (rsp.uuid));

        ret = glusterd_friend_find (rsp.uuid, NULL, &peerinfo);

        if (ret) {
                gf_log (this->name, GF_LOG_CRITICAL, "Lock response received "
                        "from unknown peer: %s", uuid_utoa (rsp.uuid));
        }

        if (op_ret) {
                event_type = GD_OP_EVENT_RCVD_RJT;
                opinfo.op_ret = op_ret;
                opinfo.op_errstr = gf_strdup ("Another transaction could be in "
                                              "progress. Please try again after"
                                              " sometime.");
        } else {
                event_type = GD_OP_EVENT_RCVD_ACC;
        }

        ret = glusterd_op_sm_inject_event (event_type, NULL);

        if (!ret) {
                glusterd_friend_sm ();
                glusterd_op_sm ();
        }

        GLUSTERD_STACK_DESTROY (((call_frame_t *)myframe));
        return ret;
}

int32_t
glusterd_cluster_unlock_cbk (struct rpc_req *req, struct iovec *iov,
                                 int count, void *myframe)
{
        gd1_mgmt_cluster_lock_rsp     rsp   = {{0},};
        int                           ret   = -1;
        int32_t                       op_ret = -1;
        glusterd_op_sm_event_type_t   event_type = GD_OP_EVENT_NONE;
        glusterd_peerinfo_t           *peerinfo = NULL;
        xlator_t                      *this = NULL;

        this = THIS;
        GF_ASSERT (this);
        GF_ASSERT (req);

        if (-1 == req->rpc_status) {
                rsp.op_ret   = -1;
                rsp.op_errno = EINVAL;
                goto out;
        }

        ret = xdr_to_generic (*iov, &rsp, (xdrproc_t)xdr_gd1_mgmt_cluster_unlock_rsp);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_ERROR, "Failed to decode unlock "
                        "response received from peer");
                rsp.op_ret   = -1;
                rsp.op_errno = EINVAL;
                goto out;
        }

out:
        op_ret = rsp.op_ret;

        gf_log (this->name, (op_ret) ? GF_LOG_ERROR : GF_LOG_DEBUG,
                "Received unlock %s from uuid: %s",
                (op_ret)?"RJT":"ACC", uuid_utoa (rsp.uuid));

        ret = glusterd_friend_find (rsp.uuid, NULL, &peerinfo);

        if (ret) {
                gf_log (this->name, GF_LOG_CRITICAL, "Unlock response received "
                        "from unknown peer %s", uuid_utoa (rsp.uuid));
        }

        if (op_ret) {
                event_type = GD_OP_EVENT_RCVD_RJT;
                opinfo.op_ret = op_ret;
        } else {
                event_type = GD_OP_EVENT_RCVD_ACC;
        }

        ret = glusterd_op_sm_inject_event (event_type, NULL);

        if (!ret) {
                glusterd_friend_sm ();
                glusterd_op_sm ();
        }

        GLUSTERD_STACK_DESTROY (((call_frame_t *)myframe));
        return ret;
}

int32_t
glusterd_stage_op_cbk (struct rpc_req *req, struct iovec *iov,
                          int count, void *myframe)
{
        gd1_mgmt_stage_op_rsp         rsp   = {{0},};
        int                           ret   = -1;
        int32_t                       op_ret = -1;
        glusterd_op_sm_event_type_t   event_type = GD_OP_EVENT_NONE;
        glusterd_peerinfo_t           *peerinfo = NULL;
        dict_t                        *dict   = NULL;
        char                          err_str[2048] = {0};
        char                          *peer_str = NULL;
        xlator_t                      *this = NULL;

        this = THIS;
        GF_ASSERT (this);
        GF_ASSERT (req);

        if (-1 == req->rpc_status) {
                rsp.op_ret   = -1;
                rsp.op_errno = EINVAL;
                /* use standard allocation because to keep uniformity
                   in freeing it */
                rsp.op_errstr = strdup ("error");
                goto out;
        }

        ret = xdr_to_generic (*iov, &rsp, (xdrproc_t)xdr_gd1_mgmt_stage_op_rsp);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_ERROR, "Failed to decode stage "
                        "response received from peer");
                rsp.op_ret   = -1;
                rsp.op_errno = EINVAL;
                /* use standard allocation because to keep uniformity
                   in freeing it */
                rsp.op_errstr = strdup ("Failed to decode stage response "
                                        "received from peer.");
                goto out;
        }

        if (rsp.dict.dict_len) {
                /* Unserialize the dictionary */
                dict  = dict_new ();

                ret = dict_unserialize (rsp.dict.dict_val,
                                        rsp.dict.dict_len,
                                        &dict);
                if (ret < 0) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "failed to "
                                "unserialize rsp-buffer to dictionary");
			event_type = GD_OP_EVENT_RCVD_RJT;
                        goto out;
                } else {
                        dict->extra_stdfree = rsp.dict.dict_val;
                }
        }

out:
        op_ret = rsp.op_ret;

        gf_log (this->name, (op_ret) ? GF_LOG_ERROR : GF_LOG_DEBUG,
                "Received stage %s from uuid: %s",
                (op_ret) ? "RJT" : "ACC", uuid_utoa (rsp.uuid));

        ret = glusterd_friend_find (rsp.uuid, NULL, &peerinfo);

        if (ret) {
                gf_log (this->name, GF_LOG_CRITICAL, "Stage response received "
                        "from unknown peer: %s", uuid_utoa (rsp.uuid));
        }

        if (op_ret) {
                event_type = GD_OP_EVENT_RCVD_RJT;
                opinfo.op_ret = op_ret;
                if (strcmp ("", rsp.op_errstr)) {
                        opinfo.op_errstr = gf_strdup (rsp.op_errstr);
                } else {
                        if (peerinfo)
                                peer_str = peerinfo->hostname;
                        else
                                peer_str = uuid_utoa (rsp.uuid);
                        snprintf (err_str, sizeof (err_str),
                                  OPERRSTR_STAGE_FAIL, peer_str);
                        opinfo.op_errstr = gf_strdup (err_str);
                }
                if (!opinfo.op_errstr) {
                        ret = -1;
                        goto out;
                }
        } else {
                event_type = GD_OP_EVENT_RCVD_ACC;
        }

        switch (rsp.op) {
        case GD_OP_REPLACE_BRICK:
                glusterd_rb_use_rsp_dict (NULL, dict);
                break;
        }

        ret = glusterd_op_sm_inject_event (event_type, NULL);

        if (!ret) {
                glusterd_friend_sm ();
                glusterd_op_sm ();
        }

        free (rsp.op_errstr); //malloced by xdr
        if (dict) {
                if (!dict->extra_stdfree && rsp.dict.dict_val)
                        free (rsp.dict.dict_val); //malloced by xdr
                dict_unref (dict);
        } else {
                free (rsp.dict.dict_val); //malloced by xdr
        }
        GLUSTERD_STACK_DESTROY (((call_frame_t *)myframe));
        return ret;
}

int32_t
glusterd_commit_op_cbk (struct rpc_req *req, struct iovec *iov,
                          int count, void *myframe)
{
        gd1_mgmt_commit_op_rsp         rsp   = {{0},};
        int                           ret   = -1;
        int32_t                       op_ret = -1;
        glusterd_op_sm_event_type_t   event_type = GD_OP_EVENT_NONE;
        glusterd_peerinfo_t           *peerinfo = NULL;
        dict_t                        *dict = NULL;
        char                          err_str[2048] = {0};
        char                          *peer_str = NULL;
        xlator_t                      *this = NULL;

        this = THIS;
        GF_ASSERT (this);
        GF_ASSERT (req);

        if (-1 == req->rpc_status) {
                rsp.op_ret   = -1;
                rsp.op_errno = EINVAL;
                /* use standard allocation because to keep uniformity
                   in freeing it */
                rsp.op_errstr = strdup ("error");
		event_type = GD_OP_EVENT_RCVD_RJT;
                goto out;
        }

        ret = xdr_to_generic (*iov, &rsp, (xdrproc_t)xdr_gd1_mgmt_commit_op_rsp);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_ERROR, "Failed to decode commit "
                        "response received from peer");
                rsp.op_ret   = -1;
                rsp.op_errno = EINVAL;
                /* use standard allocation because to keep uniformity
                   in freeing it */
                rsp.op_errstr = strdup ("Failed to decode commit response "
                                        "received from peer.");
		event_type = GD_OP_EVENT_RCVD_RJT;
                goto out;
        }

        if (rsp.dict.dict_len) {
                /* Unserialize the dictionary */
                dict  = dict_new ();

                ret = dict_unserialize (rsp.dict.dict_val,
                                        rsp.dict.dict_len,
                                        &dict);
                if (ret < 0) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "failed to "
                                "unserialize rsp-buffer to dictionary");
			event_type = GD_OP_EVENT_RCVD_RJT;
                        goto out;
                } else {
                        dict->extra_stdfree = rsp.dict.dict_val;
                }
        }

        op_ret = rsp.op_ret;

        gf_log (this->name, (op_ret) ? GF_LOG_ERROR : GF_LOG_DEBUG,
                "Received commit %s from uuid: %s",
                (op_ret)?"RJT":"ACC", uuid_utoa (rsp.uuid));

        ret = glusterd_friend_find (rsp.uuid, NULL, &peerinfo);

        if (ret) {
                gf_log (this->name, GF_LOG_CRITICAL, "Commit response for "
                        "'Volume %s' received from unknown peer: %s",
                        gd_op_list[opinfo.op], uuid_utoa (rsp.uuid));
        }

        if (op_ret) {
                event_type = GD_OP_EVENT_RCVD_RJT;
                opinfo.op_ret = op_ret;
                if (strcmp ("", rsp.op_errstr)) {
                        opinfo.op_errstr = gf_strdup(rsp.op_errstr);
                } else {
                        if (peerinfo)
                                peer_str = peerinfo->hostname;
                        else
                                peer_str = uuid_utoa (rsp.uuid);
                        snprintf (err_str, sizeof (err_str),
                                  OPERRSTR_COMMIT_FAIL, peer_str);
                        opinfo.op_errstr = gf_strdup (err_str);
                }
                if (!opinfo.op_errstr) {
                        ret = -1;
                        goto out;
                }
        } else {
                event_type = GD_OP_EVENT_RCVD_ACC;
                switch (rsp.op) {
                case GD_OP_REPLACE_BRICK:
                        ret = glusterd_rb_use_rsp_dict (NULL, dict);
                        if (ret)
                                goto out;
                break;

                case GD_OP_SYNC_VOLUME:
                        ret = glusterd_sync_use_rsp_dict (NULL, dict);
                        if (ret)
                                goto out;
                break;

                case GD_OP_PROFILE_VOLUME:
                        ret = glusterd_profile_volume_use_rsp_dict (NULL, dict);
                        if (ret)
                                goto out;
                break;

                case GD_OP_GSYNC_SET:
                        ret = glusterd_gsync_use_rsp_dict (NULL, dict, rsp.op_errstr);
                        if (ret)
                                goto out;
                break;

                case GD_OP_STATUS_VOLUME:
                        ret = glusterd_volume_status_copy_to_op_ctx_dict (NULL, dict);
                        if (ret)
                                goto out;
                break;

                case GD_OP_REBALANCE:
                case GD_OP_DEFRAG_BRICK_VOLUME:
                        ret = glusterd_volume_rebalance_use_rsp_dict (NULL, dict);
                        if (ret)
                                goto out;
                break;

                case GD_OP_HEAL_VOLUME:
                        ret = glusterd_volume_heal_use_rsp_dict (NULL, dict);
                        if (ret)
                                goto out;

                break;

                default:
                break;
                }
        }

out:
        ret = glusterd_op_sm_inject_event (event_type, NULL);

        if (!ret) {
                glusterd_friend_sm ();
                glusterd_op_sm ();
        }

        if (dict)
                dict_unref (dict);
        free (rsp.op_errstr); //malloced by xdr
        GLUSTERD_STACK_DESTROY (((call_frame_t *)myframe));
        return ret;
}


int32_t
glusterd_cluster_lock (call_frame_t *frame, xlator_t *this,
                          void *data)
{
        gd1_mgmt_cluster_lock_req       req = {{0},};
        int                             ret = -1;
        glusterd_peerinfo_t             *peerinfo = NULL;
        glusterd_conf_t                 *priv = NULL;
        call_frame_t                    *dummy_frame = NULL;

        if (!this)
                goto out;

        peerinfo = data;

        priv = this->private;
        GF_ASSERT (priv);

        glusterd_get_uuid (&req.uuid);

        dummy_frame = create_frame (this, this->ctx->pool);
        if (!dummy_frame)
                goto out;

        ret = glusterd_submit_request (peerinfo->rpc, &req, dummy_frame,
                                       peerinfo->mgmt, GLUSTERD_MGMT_CLUSTER_LOCK,
                                       NULL,
                                       this, glusterd_cluster_lock_cbk,
                                       (xdrproc_t)xdr_gd1_mgmt_cluster_lock_req);
out:
        gf_log (this->name, GF_LOG_DEBUG, "Returning %d", ret);
        return ret;
}

int32_t
glusterd_cluster_unlock (call_frame_t *frame, xlator_t *this,
                            void *data)
{
        gd1_mgmt_cluster_lock_req       req = {{0},};
        int                             ret = -1;
        glusterd_peerinfo_t             *peerinfo = NULL;
        glusterd_conf_t                 *priv = NULL;
        call_frame_t                    *dummy_frame = NULL;

        if (!this ) {
                ret = -1;
                goto out;
        }
        peerinfo = data;
        priv = this->private;
        GF_ASSERT (priv);

        glusterd_get_uuid (&req.uuid);

        dummy_frame = create_frame (this, this->ctx->pool);
        if (!dummy_frame)
                goto out;

        ret = glusterd_submit_request (peerinfo->rpc, &req, dummy_frame,
                                       peerinfo->mgmt, GLUSTERD_MGMT_CLUSTER_UNLOCK,
                                       NULL,
                                       this, glusterd_cluster_unlock_cbk,
                                       (xdrproc_t)xdr_gd1_mgmt_cluster_unlock_req);
out:
        gf_log (this->name, GF_LOG_DEBUG, "Returning %d", ret);
        return ret;
}

int32_t
glusterd_stage_op (call_frame_t *frame, xlator_t *this,
                      void *data)
{
        gd1_mgmt_stage_op_req           req = {{0,},};
        int                             ret = -1;
        glusterd_peerinfo_t             *peerinfo = NULL;
        glusterd_conf_t                 *priv = NULL;
        call_frame_t                    *dummy_frame = NULL;
        dict_t                          *dict = NULL;
        gf_boolean_t                    is_alloc = _gf_true;

        if (!this) {
                goto out;
        }

        dict = data;

        priv = this->private;
        GF_ASSERT (priv);

        ret = dict_get_ptr (dict, "peerinfo", VOID (&peerinfo));
        if (ret)
                goto out;

        //peerinfo should not be in payload
        dict_del (dict, "peerinfo");

        glusterd_get_uuid (&req.uuid);
        req.op = glusterd_op_get_op ();

        ret = dict_allocate_and_serialize (dict, &req.buf.buf_val,
                                           &req.buf.buf_len);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "Failed to serialize dict "
                        "to request buffer");
                goto out;
        }


        dummy_frame = create_frame (this, this->ctx->pool);
        if (!dummy_frame)
                goto out;

        ret = glusterd_submit_request (peerinfo->rpc, &req, dummy_frame,
                                       peerinfo->mgmt, GLUSTERD_MGMT_STAGE_OP,
                                       NULL,
                                       this, glusterd_stage_op_cbk,
                                       (xdrproc_t)xdr_gd1_mgmt_stage_op_req);

out:
        if ((_gf_true == is_alloc) && req.buf.buf_val)
                GF_FREE (req.buf.buf_val);

        gf_log (this->name, GF_LOG_DEBUG, "Returning %d", ret);
        return ret;
}

int32_t
glusterd_commit_op (call_frame_t *frame, xlator_t *this,
                      void *data)
{
        gd1_mgmt_commit_op_req  req         = {{0,},};
        int                     ret         = -1;
        glusterd_peerinfo_t    *peerinfo    = NULL;
        glusterd_conf_t        *priv        = NULL;
        call_frame_t           *dummy_frame = NULL;
        dict_t                 *dict        = NULL;
        gf_boolean_t            is_alloc    = _gf_true;

        if (!this) {
                goto out;
        }

        dict = data;
        priv = this->private;
        GF_ASSERT (priv);

        ret = dict_get_ptr (dict, "peerinfo", VOID (&peerinfo));
        if (ret)
                goto out;

        //peerinfo should not be in payload
        dict_del (dict, "peerinfo");

        glusterd_get_uuid (&req.uuid);
        req.op = glusterd_op_get_op ();

        ret = dict_allocate_and_serialize (dict, &req.buf.buf_val,
                                           &req.buf.buf_len);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "Failed to serialize dict to "
                        "request buffer");
                goto out;
        }

        dummy_frame = create_frame (this, this->ctx->pool);
        if (!dummy_frame)
                goto out;

        ret = glusterd_submit_request (peerinfo->rpc, &req, dummy_frame,
                                       peerinfo->mgmt, GLUSTERD_MGMT_COMMIT_OP,
                                       NULL,
                                       this, glusterd_commit_op_cbk,
                                       (xdrproc_t)xdr_gd1_mgmt_commit_op_req);

out:
        if ((_gf_true == is_alloc) && req.buf.buf_val)
                GF_FREE (req.buf.buf_val);

        gf_log (this->name, GF_LOG_DEBUG, "Returning %d", ret);
        return ret;
}

int32_t
glusterd_brick_op_cbk (struct rpc_req *req, struct iovec *iov,
                          int count, void *myframe)
{
        gd1_mgmt_brick_op_rsp         rsp   = {0};
        int                           ret   = -1;
        int32_t                       op_ret = -1;
        glusterd_op_sm_event_type_t   event_type = GD_OP_EVENT_NONE;
        call_frame_t                  *frame = NULL;
        glusterd_op_brick_rsp_ctx_t   *ev_ctx = NULL;
        dict_t                        *dict = NULL;
        int                           index = 0;
        glusterd_req_ctx_t            *req_ctx = NULL;
        glusterd_pending_node_t       *node = NULL;
        xlator_t                      *this = NULL;

        this = THIS;
        GF_ASSERT (this);

        GF_ASSERT (req);
        frame = myframe;
        req_ctx = frame->local;

        if (-1 == req->rpc_status) {
                rsp.op_ret   = -1;
                rsp.op_errno = EINVAL;
                /* use standard allocation because to keep uniformity
                   in freeing it */
                rsp.op_errstr = strdup ("error");
		event_type = GD_OP_EVENT_RCVD_RJT;
                goto out;
        }

        ret =  xdr_to_generic (*iov, &rsp, (xdrproc_t)xdr_gd1_mgmt_brick_op_rsp);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_ERROR, "Failed to decode brick op "
                        "response received");
                rsp.op_ret   = -1;
                rsp.op_errno = EINVAL;
                rsp.op_errstr = strdup ("Unable to decode brick op response");
		event_type = GD_OP_EVENT_RCVD_RJT;
                goto out;
        }

        if (rsp.output.output_len) {
                /* Unserialize the dictionary */
                dict  = dict_new ();

                ret = dict_unserialize (rsp.output.output_val,
                                        rsp.output.output_len,
                                        &dict);
                if (ret < 0) {
                        gf_log (this->name, GF_LOG_ERROR, "Failed to "
                                "unserialize rsp-buffer to dictionary");
			event_type = GD_OP_EVENT_RCVD_RJT;
                        goto out;
                } else {
                        dict->extra_stdfree = rsp.output.output_val;
                }
        }

        op_ret = rsp.op_ret;

        /* Add index to rsp_dict for GD_OP_STATUS_VOLUME */
        if (GD_OP_STATUS_VOLUME == req_ctx->op) {
                node = frame->cookie;
                index = node->index;
                ret = dict_set_int32 (dict, "index", index);
                if (ret) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "Error setting index on brick status rsp dict");
                        rsp.op_ret = -1;
                        event_type = GD_OP_EVENT_RCVD_RJT;
                        goto out;
                }
        }
out:
        ev_ctx = GF_CALLOC (1, sizeof (*ev_ctx), gf_gld_mt_brick_rsp_ctx_t);
        GF_ASSERT (ev_ctx);
        if (op_ret) {
                event_type = GD_OP_EVENT_RCVD_RJT;
                ev_ctx->op_ret = op_ret;
                ev_ctx->op_errstr = gf_strdup(rsp.op_errstr);
        } else {
                event_type = GD_OP_EVENT_RCVD_ACC;
        }
        ev_ctx->pending_node = frame->cookie;
        ev_ctx->rsp_dict  = dict;
        ev_ctx->commit_ctx = frame->local;
        ret = glusterd_op_sm_inject_event (event_type, ev_ctx);
        if (!ret) {
                glusterd_friend_sm ();
                glusterd_op_sm ();
        }

        if (ret && dict)
                dict_unref (dict);
        free (rsp.op_errstr); //malloced by xdr
        GLUSTERD_STACK_DESTROY (frame);
        return ret;
}

int32_t
glusterd_brick_op (call_frame_t *frame, xlator_t *this,
                      void *data)
{
        gd1_mgmt_brick_op_req           *req = NULL;
        int                             ret = 0;
        glusterd_conf_t                 *priv = NULL;
        call_frame_t                    *dummy_frame = NULL;
        char                            *op_errstr = NULL;
        int                             pending_bricks = 0;
        glusterd_pending_node_t         *pending_node;
        glusterd_req_ctx_t              *req_ctx = NULL;
        struct rpc_clnt                 *rpc = NULL;
        dict_t                          *op_ctx = NULL;

        if (!this) {
                ret = -1;
                goto out;
        }
        priv = this->private;
        GF_ASSERT (priv);

        req_ctx = data;
        GF_ASSERT (req_ctx);
        INIT_LIST_HEAD (&opinfo.pending_bricks);
        ret = glusterd_op_bricks_select (req_ctx->op, req_ctx->dict, &op_errstr,
                                         &opinfo.pending_bricks, NULL);

        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "Failed to select bricks "
                        "while performing brick op during 'Volume %s'",
                        gd_op_list[opinfo.op]);
                opinfo.op_errstr = op_errstr;
                goto out;
        }

        list_for_each_entry (pending_node, &opinfo.pending_bricks, list) {
                dummy_frame = create_frame (this, this->ctx->pool);
                if (!dummy_frame)
                        continue;

                if ((pending_node->type == GD_NODE_NFS) ||
                    ((pending_node->type == GD_NODE_SHD) &&
                    (req_ctx->op == GD_OP_STATUS_VOLUME)))
                        ret = glusterd_node_op_build_payload
                                (req_ctx->op,
                                 (gd1_mgmt_brick_op_req **)&req,
                                 req_ctx->dict);
                else {
                        ret = glusterd_brick_op_build_payload
                                (req_ctx->op, pending_node->node,
                                 (gd1_mgmt_brick_op_req **)&req,
                                 req_ctx->dict);

                        if (ret) {
                                gf_log (this->name, GF_LOG_ERROR, "Failed to "
                                        "build brick op payload during "
                                        "'Volume %s'", gd_op_list[req_ctx->op]);
                                goto out;
                        }
                }

                dummy_frame->local = data;
                dummy_frame->cookie = pending_node;

                rpc = glusterd_pending_node_get_rpc (pending_node);
                if (!rpc) {
                        if (pending_node->type == GD_NODE_REBALANCE) {
                                opinfo.brick_pending_count = 0;
                                ret = 0;
                                if (req) {
                                        GF_FREE (req->input.input_val);
                                        GF_FREE (req);
                                        req = NULL;
                                }
                                GLUSTERD_STACK_DESTROY (dummy_frame);

                                op_ctx = glusterd_op_get_ctx ();
                                if (!op_ctx)
                                        goto out;
                                glusterd_defrag_volume_node_rsp (req_ctx->dict,
                                                                 NULL, op_ctx);

                                goto out;
                        }

                        ret = -1;
                        gf_log (this->name, GF_LOG_ERROR, "Brick Op failed "
                                "due to rpc failure.");
                        goto out;
                }

                ret = glusterd_submit_request (rpc, req, dummy_frame,
                                               priv->gfs_mgmt,
                                               req->op, NULL,
                                               this, glusterd_brick_op_cbk,
                                               (xdrproc_t)xdr_gd1_mgmt_brick_op_req);
                if (req) {
                        GF_FREE (req->input.input_val);
                        GF_FREE (req);
                        req = NULL;
                }
                if (!ret)
                        pending_bricks++;
        }

        gf_log (this->name, GF_LOG_DEBUG, "Sent brick op req for operation "
                "'Volume %s' to %d bricks", gd_op_list[req_ctx->op],
                pending_bricks);
        opinfo.brick_pending_count = pending_bricks;

out:
        if (ret) {
                glusterd_op_sm_inject_event (GD_OP_EVENT_RCVD_RJT, data);
                opinfo.op_ret = ret;
        }
        gf_log (this->name, GF_LOG_DEBUG, "Returning %d", ret);
        return ret;
}


struct rpc_clnt_procedure gd_brick_actors[GLUSTERD_BRICK_MAXVALUE] = {
        [GLUSTERD_BRICK_NULL] = {"NULL", NULL },
        [GLUSTERD_BRICK_OP]   = {"BRICK_OP", glusterd_brick_op},
};

struct rpc_clnt_procedure gd_mgmt_actors[GLUSTERD_MGMT_MAXVALUE] = {
        [GLUSTERD_MGMT_NULL]           = {"NULL", NULL },
        [GLUSTERD_MGMT_CLUSTER_LOCK]   = {"CLUSTER_LOCK", glusterd_cluster_lock},
        [GLUSTERD_MGMT_CLUSTER_UNLOCK] = {"CLUSTER_UNLOCK", glusterd_cluster_unlock},
        [GLUSTERD_MGMT_STAGE_OP]       = {"STAGE_OP", glusterd_stage_op},
        [GLUSTERD_MGMT_COMMIT_OP]      = {"COMMIT_OP", glusterd_commit_op},
};

struct rpc_clnt_program gd_mgmt_prog = {
        .progname  = "glusterd mgmt",
        .prognum   = GD_MGMT_PROGRAM,
        .progver   = GD_MGMT_VERSION,
        .proctable = gd_mgmt_actors,
        .numproc   = GLUSTERD_MGMT_MAXVALUE,
};

struct rpc_clnt_program gd_brick_prog = {
        .progname  = "brick operations",
        .prognum   = GD_BRICK_PROGRAM,
        .progver   = GD_BRICK_VERSION,
        .proctable = gd_brick_actors,
        .numproc   = GLUSTERD_BRICK_MAXVALUE,
};
