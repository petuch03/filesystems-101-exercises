#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <liburing.h>

// DEBUG_PRINT( printf("chunk_size: %zu offset: %zu\n", chunk_size, current_offset) )
// DEBUG_PRINT( printf("[DBG] submitted_cnt=%d\n", submitted) )

#define CHUNK_SIZE (256 * 1024)  // 256K chunks
#define MAX_INFLIGHT 4

typedef struct transfer_ctx {
    size_t offset;
    int is_read;
    void *buf;
    struct iovec vec;
} transfer_ctx;

static inline int init_uring_queue(struct io_uring *ring) {
    return io_uring_queue_init(MAX_INFLIGHT, ring, 0);
}

static inline off_t get_src_size(int fd) {
    struct stat st;
    if (fstat(fd, &st) != 0)
        return -1;
    return st.st_size;
}

static int queue_read_op(struct io_uring *ring, int fd, transfer_ctx *ctx, size_t size) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) return -1;

    ctx->buf = malloc(size + sizeof(transfer_ctx));
    if (!ctx->buf) return -ENOMEM;

    ctx->is_read = 1;
    ctx->vec.iov_base = ctx->buf;
    ctx->vec.iov_len = size;

    // printf("[DBG] Queueing read: off=%lu size=%lu\n", ctx->offset, size);
    io_uring_prep_readv(sqe, fd, &ctx->vec, 1, ctx->offset);
    io_uring_sqe_set_data(sqe, ctx);
    return 0;
}

static int queue_write_op(struct io_uring *ring, int fd, transfer_ctx *ctx, size_t bytes) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) return -1;

    ctx->is_read = 0;
    ctx->vec.iov_len = bytes;

    io_uring_prep_writev(sqe, fd, &ctx->vec, 1, ctx->offset);
    io_uring_sqe_set_data(sqe, ctx);

    return io_uring_submit(ring);
}

int copy(int src_fd, int dst_fd) {
    struct io_uring ring;
    struct io_uring_cqe *cqe;
    off_t total_size, remaining;
    size_t curr_off = 0;
    int active_xfers = 0;
    int pending_writes = 0;
    int ret;

    // printf("[DBG] Starting copy operation\n");

    if ((total_size = get_src_size(src_fd)) < 0)
        return -errno;

    if (init_uring_queue(&ring) < 0)
        return -errno;

    remaining = total_size;

    // Queue initial reads
    for (int i = 0; i < MAX_INFLIGHT && remaining > 0; i++) {
        transfer_ctx *ctx = calloc(1, sizeof(transfer_ctx));
        if (!ctx) return -ENOMEM;

        size_t chunk = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : remaining;
        ctx->offset = curr_off;

        if (queue_read_op(&ring, src_fd, ctx, chunk) < 0) {
            free(ctx);
            return -errno;
        }

        curr_off += chunk;
        remaining -= chunk;
        active_xfers++;
    }

    if ((ret = io_uring_submit(&ring)) < 0) {
        io_uring_queue_exit(&ring);
        return ret;
    }

    pending_writes = active_xfers;

    while (active_xfers > 0) {
        ret = io_uring_wait_cqe(&ring, &cqe);
        if (ret < 0) break;

        transfer_ctx *ctx = io_uring_cqe_get_data(cqe);
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

            if (queue_write_op(&ring, dst_fd, ctx, bytes) < 0) {
                ret = -errno;
                free(ctx->buf);
                free(ctx);
                break;
            }

            if (remaining > 0) {
                transfer_ctx *new_ctx = calloc(1, sizeof(transfer_ctx));
                if (!new_ctx) {
                    ret = -ENOMEM;
                    break;
                }

                size_t chunk = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : remaining;
                new_ctx->offset = curr_off;

                if (queue_read_op(&ring, src_fd, new_ctx, chunk) < 0) {
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

    io_uring_queue_exit(&ring);
    return ret ? ret : 0;
}