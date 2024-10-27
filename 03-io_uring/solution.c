#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <liburing.h>

#define BUFFER_SZ (256 * 1024)
#define QUEUE_DEPTH 4

struct xfer_ctx {
    char *buf;
    size_t len;
    off_t pos;
    int is_read;
} __attribute__((aligned(8)));

static inline int setup_ring(struct io_uring *ring) {
    //DBG_LOG("init ring with qd=%d", QUEUE_DEPTH);
    return io_uring_queue_init(QUEUE_DEPTH, ring, 0);
}

static off_t get_input_size(int fd) {
    struct stat st;
    return fstat(fd, &st) == 0 ? st.st_size : -1;
}

static int push_read(struct io_uring *ring, int fd, struct xfer_ctx *ctx, size_t bytes) {
    struct io_uring_sqe *sqe;
    
    //DBG_LOG("push read: pos=%lu sz=%lu", ctx->pos, bytes);
    
    if (!(sqe = io_uring_get_sqe(ring)))
        return -1;
        
    ctx->buf = malloc(bytes);
    if (!ctx->buf)
        return -ENOMEM;
    
    ctx->len = bytes;
    ctx->is_read = 1;
    
    io_uring_prep_read(sqe, fd, ctx->buf, bytes, ctx->pos);
    io_uring_sqe_set_data(sqe, ctx);
    
    return 0;
}

static int push_write(struct io_uring *ring, int fd, struct xfer_ctx *ctx) {
    struct io_uring_sqe *sqe;
    
    //DBG_LOG("push write: pos=%lu sz=%lu", ctx->pos, ctx->len);
    
    if (!(sqe = io_uring_get_sqe(ring)))
        return -1;
    
    ctx->is_read = 0;
    
    io_uring_prep_write(sqe, fd, ctx->buf, ctx->len, ctx->pos);
    io_uring_sqe_set_data(sqe, ctx);
    
    return io_uring_submit(ring);
}

int copy(int in_fd, int out_fd) {
    struct io_uring ring;
    struct io_uring_cqe *cqe;
    off_t total_sz, remaining;
    size_t curr_off = 0;
    int active_xfers = 0;
    int pending_writes = 0;
    int ret = 0;
    
    //DBG_LOG("starting copy operation");
    
    total_sz = get_input_size(in_fd);
    if (total_sz < 0)
        return -errno;
    
    if (setup_ring(&ring) < 0)
        return -errno;
        
    remaining = total_sz;
    
    // Initial read batch
    for (int i = 0; i < QUEUE_DEPTH && remaining > 0; i++) {
        struct xfer_ctx *ctx = malloc(sizeof(*ctx));
        if (!ctx) {
            ret = -ENOMEM;
            goto cleanup;
        }
        
        size_t chunk = remaining > BUFFER_SZ ? BUFFER_SZ : remaining;
        ctx->pos = curr_off;
        
        if (push_read(&ring, in_fd, ctx, chunk) < 0) {
            free(ctx);
            ret = -errno;
            goto cleanup;
        }
        
        curr_off += chunk;
        remaining -= chunk;
        active_xfers++;
    }
    
    //DBG_LOG("queued initial %d reads", active_xfers);
    
    if ((ret = io_uring_submit(&ring)) < 0)
        goto cleanup;
    pending_writes = active_xfers;
    while (active_xfers > 0) {
        ret = io_uring_wait_cqe(&ring, &cqe);
        if (ret < 0)
            break;
        struct xfer_ctx *ctx = io_uring_cqe_get_data(cqe);
        int bytes = cqe->res;
        io_uring_cqe_seen(&ring, cqe);

        if (bytes < 0) {
            ret = bytes;
            free(ctx->buf);
            free(ctx);
            break;
        }
        if (ctx->is_read) {
            pending_writes--;
            ctx->len = bytes;  // actual bytes read
            
            if (push_write(&ring, out_fd, ctx) < 0) {
                ret = -errno;
                free(ctx->buf);
                free(ctx);
                break;
            }
            
            if (remaining > 0) {
                struct xfer_ctx *new_ctx = malloc(sizeof(*new_ctx));
                if (!new_ctx) {
                    ret = -ENOMEM;
                    break;
                }
                
                size_t chunk = remaining > BUFFER_SZ ? BUFFER_SZ : remaining;
                new_ctx->pos = curr_off;
                
                if (push_read(&ring, in_fd, new_ctx, chunk) < 0) {
                    free(new_ctx);
                    ret = -errno;
                    break;
                }

                curr_off += chunk;
                remaining -= chunk;
                pending_writes++;
            }
        } else {
            active_xfers--;
            free(ctx->buf);
            free(ctx);
        }
    }

cleanup:
    //DBG_LOG("cleanup: ret=%d", ret);
    io_uring_queue_exit(&ring);
    return ret;
}