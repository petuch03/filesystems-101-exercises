#include <solution.h>
#include <liburing.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "stdlib/fs_malloc.h"

#define COPY_BLOCK_SIZE (256 * 1024)  // 256KB blocks
#define QUEUE_DEPTH 4

struct io_data {
    char *buf;
    size_t size;
    off_t offset;
    int read_done;
};

int copy(int in, int out) {
    struct io_uring ring;
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    struct io_data *data[QUEUE_DEPTH] = {0};
    int ret, i, pending = 0;

    ret = io_uring_queue_init(QUEUE_DEPTH * 2, &ring, 0);
    if (ret < 0)
        return -errno;

    for (i = 0; i < QUEUE_DEPTH; i++) {
        data[i] = fs_xmalloc(sizeof(struct io_data));
        data[i]->buf = fs_xmalloc(COPY_BLOCK_SIZE);
        data[i]->offset = i * COPY_BLOCK_SIZE;
        data[i]->read_done = 0;
    }

    // Submit initial read requests
    for (i = 0; i < QUEUE_DEPTH; i++) {
        sqe = io_uring_get_sqe(&ring);
        if (!sqe) {
            ret = -EAGAIN;
            goto cleanup;
        }
        io_uring_prep_read(sqe, in, data[i]->buf, COPY_BLOCK_SIZE, data[i]->offset);
        io_uring_sqe_set_data(sqe, data[i]);
        pending++;
    }

    ret = io_uring_submit(&ring);
    if (ret < 0) {
        ret = -errno;
        goto cleanup;
    }

    off_t next_offset = QUEUE_DEPTH * COPY_BLOCK_SIZE;

    while (pending > 0) {
        ret = io_uring_wait_cqe(&ring, &cqe);
        if (ret < 0) {
            ret = -errno;
            goto cleanup;
        }

        struct io_data *current = io_uring_cqe_get_data(cqe);
        int bytes = cqe->res;
        io_uring_cqe_seen(&ring, cqe);

        if (bytes < 0) {
            ret = bytes;
            goto cleanup;
        }

        pending--;

        if (!current->read_done) {
            current->size = bytes;
            current->read_done = 1;

            if (bytes > 0) {
                // Submit write
                sqe = io_uring_get_sqe(&ring);
                if (!sqe) {
                    ret = -EAGAIN;
                    goto cleanup;
                }
                io_uring_prep_write(sqe, out, current->buf, bytes, current->offset);
                io_uring_sqe_set_data(sqe, current);
                pending++;
            }
        } else {
            if (current->size == COPY_BLOCK_SIZE) {
                sqe = io_uring_get_sqe(&ring);
                if (!sqe) {
                    ret = -EAGAIN;
                    goto cleanup;
                }
                current->offset = next_offset;
                current->read_done = 0;
                io_uring_prep_read(sqe, in, current->buf, COPY_BLOCK_SIZE, next_offset);
                io_uring_sqe_set_data(sqe, current);
                next_offset += COPY_BLOCK_SIZE;
                pending++;
            }
        }

        ret = io_uring_submit(&ring);
        if (ret < 0) {
            ret = -errno;
            goto cleanup;
        }
    }

    ret = 0;

cleanup:
    while (pending > 0) {
        ret = io_uring_wait_cqe(&ring, &cqe);
        if (ret < 0) {
            ret = -errno;
            break;
        }
        io_uring_cqe_seen(&ring, cqe);
        pending--;
    }

    for (i = 0; i < QUEUE_DEPTH; i++) {
        free(data[i]->buf);
        free(data[i]);
    }
    io_uring_queue_exit(&ring);
    return ret;
}