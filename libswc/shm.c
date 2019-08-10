/* swc: libswc/shm.c
 *
 * Copyright (c) 2013, 2014 Michael Forney
 *
 * Based in part upon wayland-shm.c from wayland, which is:
 *
 *     Copyright © 2008 Kristian Høgsberg
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "shm.h"
#include "internal.h"
#include "util.h"
#include "wayland_buffer.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <wayland-server.h>
#include <wld/pixman.h>
#include <wld/wld.h>

struct swc_shm swc_shm;

static struct {
	struct wl_global *global;
} shm;

struct pool {
	struct wl_resource *resource;
	void *data;
	size_t size;
	unsigned references;
};

struct pool_reference {
	struct wld_destructor destructor;
	struct pool *pool;
};

static void
unref_pool(struct pool *pool)
{
	if (--pool->references > 0)
		return;

	munmap(pool->data, pool->size);
	free(pool);
}

static void
destroy_pool_resource(struct wl_resource *resource)
{
	struct pool *pool = wl_resource_get_user_data(resource);
	unref_pool(pool);
}

static void
handle_buffer_destroy(struct wld_destructor *destructor)
{
	struct pool_reference *reference = wl_container_of(destructor, reference, destructor);
	unref_pool(reference->pool);
}

static inline uint32_t
format_shm_to_wld(uint32_t format)
{
	switch (format) {
	case WL_SHM_FORMAT_ARGB8888:
		return WLD_FORMAT_ARGB8888;
	case WL_SHM_FORMAT_XRGB8888:
		return WLD_FORMAT_XRGB8888;
	default:
		return format;
	}
}

static void
create_buffer(struct wl_client *client, struct wl_resource *resource,
              uint32_t id, int32_t offset, int32_t width, int32_t height, int32_t stride, uint32_t format)
{
	struct pool *pool = wl_resource_get_user_data(resource);
	struct pool_reference *reference;
	struct wld_buffer *buffer;
	struct wl_resource *buffer_resource;
	union wld_object object;

	if (offset > pool->size || offset < 0) {
		wl_resource_post_error(resource, WL_SHM_ERROR_INVALID_STRIDE, "offset is too big or negative");
		return;
	}

	object.ptr = (void *)((uintptr_t)pool->data + offset);
	buffer = wld_import_buffer(swc.shm->context, WLD_OBJECT_DATA, object, width, height, format_shm_to_wld(format), stride);

	if (!buffer)
		goto error0;

	buffer_resource = wayland_buffer_create_resource(client, wl_resource_get_version(resource), id, buffer);

	if (!buffer_resource)
		goto error1;

	if (!(reference = malloc(sizeof(*reference))))
		goto error2;

	reference->pool = pool;
	reference->destructor.destroy = &handle_buffer_destroy;
	wld_buffer_add_destructor(buffer, &reference->destructor);
	++pool->references;

	return;

error2:
	wl_resource_destroy(buffer_resource);
error1:
	wld_buffer_unreference(buffer);
error0:
	wl_resource_post_no_memory(resource);
}

static void
destroy(struct wl_client *client, struct wl_resource *resource)
{
	wl_resource_destroy(resource);
}

static void
resize(struct wl_client *client, struct wl_resource *resource, size_t size)
{
	struct pool *pool = wl_resource_get_user_data(resource);
	void *data;

#ifndef MREMAP_MAYMOVE
#define MREMAP_MAYMOVE 0
#endif
	data = mremap(pool->data, pool->size, size, MREMAP_MAYMOVE, NULL);

	if (data == MAP_FAILED) {
		wl_resource_post_error(resource, WL_SHM_ERROR_INVALID_FD, "mremap failed: %s", strerror(errno));
		return;
	}

	pool->data = data;
	pool->size = size;
}

static struct wl_shm_pool_interface shm_pool_implementation = {
	.create_buffer = create_buffer,
	.destroy = destroy,
	.resize = resize,
};

static void
create_pool(struct wl_client *client, struct wl_resource *resource, uint32_t id, int32_t fd, size_t size)
{
	struct pool *pool;

	if (!(pool = malloc(sizeof(*pool)))) {
		wl_resource_post_no_memory(resource);
		goto error0;
	}

	pool->resource = wl_resource_create(client, &wl_shm_pool_interface, wl_resource_get_version(resource), id);

	if (!pool->resource) {
		wl_resource_post_no_memory(resource);
		goto error1;
	}

	wl_resource_set_implementation(pool->resource, &shm_pool_implementation, pool, &destroy_pool_resource);
	pool->data = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (pool->data == MAP_FAILED) {
		wl_resource_post_error(resource, WL_SHM_ERROR_INVALID_FD, "mmap failed: %s", strerror(errno));
		goto error2;
	}

	close(fd);
	pool->size = size;
	pool->references = 1;
	return;

error2:
	wl_resource_destroy(pool->resource);
error1:
	free(pool);
error0:
	close(fd);
}

static struct wl_shm_interface shm_implementation = {
	.create_pool = &create_pool
};

static void
bind_shm(struct wl_client *client, void *data, uint32_t version, uint32_t id)
{
	struct wl_resource *resource;

	if (version > 1)
		version = 1;

	resource = wl_resource_create(client, &wl_shm_interface, version, id);
	wl_resource_set_implementation(resource, &shm_implementation, NULL, NULL);

	wl_shm_send_format(resource, WL_SHM_FORMAT_XRGB8888);
	wl_shm_send_format(resource, WL_SHM_FORMAT_ARGB8888);
}

bool
shm_initialize(void)
{
	if (!(swc.shm->context = wld_pixman_create_context()))
		goto error0;

	if (!(swc.shm->renderer = wld_create_renderer(swc.shm->context)))
		goto error1;

	shm.global = wl_global_create(swc.display, &wl_shm_interface, 1, NULL, &bind_shm);

	if (!shm.global)
		goto error2;

	return true;

error2:
	wld_destroy_renderer(swc.shm->renderer);
error1:
	wld_destroy_context(swc.shm->context);
error0:
	return false;
}

void
shm_finalize(void)
{
	wl_global_destroy(shm.global);
	wld_destroy_renderer(swc.shm->renderer);
	wld_destroy_context(swc.shm->context);
}
