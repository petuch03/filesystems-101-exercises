#include <solution.h>
#include <liburing.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define COPY_BLOCK_SIZE (256 * 1024)  // 256KB blocks
#define QUEUE_DEPTH 4

struct io_data {
    void *buf;
    size_t size;
    off_t offset;
    int read_done;
};

int copy(int in, int out) {
    struct io_uring ring;
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    struct io_data iodata[QUEUE_DEPTH];
    int ret = 0, pending_reads = 0, pending_writes = 0;
    off_t current_offset = 0;
    int inflight = 0;

    ret = io_uring_queue_init(QUEUE_DEPTH * 2, &ring, 0);
    if (ret < 0)
        return -errno;

    for (int i = 0; i < QUEUE_DEPTH; i++) {
        iodata[i].buf = malloc(COPY_BLOCK_SIZE);
        if (!iodata[i].buf) {
            ret = -ENOMEM;
            goto cleanup;
        }
        iodata[i].offset = 0;
        iodata[i].read_done = 0;
    }

    for (int i = 0; i < QUEUE_DEPTH; i++) {
        sqe = io_uring_get_sqe(&ring);
        if (!sqe) {
            ret = -EAGAIN;
            goto cleanup;
        }

        iodata[i].offset = current_offset;
        io_uring_prep_read(sqe, in, iodata[i].buf, COPY_BLOCK_SIZE, current_offset);
        io_uring_sqe_set_data(sqe, &iodata[i]);
        current_offset += COPY_BLOCK_SIZE;
        pending_reads++;
        inflight++;
    }

    ret = io_uring_submit(&ring);
    if (ret < 0) {
        ret = -errno;
        goto cleanup;
    }

    while (inflight > 0) {
        ret = io_uring_wait_cqe(&ring, &cqe);
        if (ret < 0) {
            ret = -errno;
            goto cleanup;
        }

        struct io_data *data = io_uring_cqe_get_data(cqe);
        int res = cqe->res;
        io_uring_cqe_seen(&ring, cqe);

        if (res < 0) {
            ret = res;
            goto cleanup;
        }

        if (!data->read_done) {
            data->size = res;
            data->read_done = 1;
            pending_reads--;

            if (res > 0) {
                sqe = io_uring_get_sqe(&ring);
                if (!sqe) {
                    ret = -EAGAIN;
                    goto cleanup;
                }

                io_uring_prep_write(sqe, out, data->buf, data->size, data->offset);
                io_uring_sqe_set_data(sqe, data);
                pending_writes++;

                if (res == COPY_BLOCK_SIZE) {
                    sqe = io_uring_get_sqe(&ring);
                    if (!sqe) {
                        ret = -EAGAIN;
                        goto cleanup;
                    }

                    struct io_data *new_data = NULL;
                    for (int i = 0; i < QUEUE_DEPTH; i++) {
                        if (!iodata[i].read_done || iodata[i].size == 0) {
                            new_data = &iodata[i];
                            break;
                        }
                    }

                    if (new_data) {
                        new_data->offset = current_offset;
                        new_data->read_done = 0;
                        io_uring_prep_read(sqe, in, new_data->buf, COPY_BLOCK_SIZE, current_offset);
                        io_uring_sqe_set_data(sqe, new_data);
                        current_offset += COPY_BLOCK_SIZE;
                        pending_reads++;
                        inflight++;
                    }
                }
            }
        } else {
            pending_writes--;
            data->size = 0;
            data->read_done = 0;
        }

        inflight = pending_reads + pending_writes;

        ret = io_uring_submit(&ring);
        if (ret < 0) {
            ret = -errno;
            goto cleanup;
        }
    }

    ret = 0;

cleanup:
    for (int i = 0; i < QUEUE_DEPTH; i++) {
        free(iodata[i].buf);
    }
    io_uring_queue_exit(&ring);
    return ret;
}