/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define HUKS_SERVICE_UID 3510
#define MAX_DIRECTORY_DEPTH 128

/* Migrate only real legacy files beneath already-open directory descriptors.
 * Never follow links or modify permissions through attacker-swappable paths. */
static int ChangeDirAndFilesPerm(int parentFd, unsigned int depth,
    uint64_t *directories, uint64_t *files)
{
    if (depth > MAX_DIRECTORY_DEPTH) {
        return -ELOOP;
    }
    int scanFd = dup(parentFd);
    if (scanFd < 0) {
        return -errno;
    }
    DIR *directory = fdopendir(scanFd);
    if (directory == NULL) {
        int status = -errno;
        (void)close(scanFd);
        return status;
    }
    int status = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            status = errno == 0 ? 0 : -errno;
            break;
        }
        if (entry->d_name[0] == '.' && (entry->d_name[1] == '\0' ||
            (entry->d_name[1] == '.' && entry->d_name[2] == '\0'))) {
            continue;
        }
        int childFd = openat(parentFd, entry->d_name,
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        if (childFd < 0) {
            status = -errno;
            break;
        }
        struct stat info;
        if (fstat(childFd, &info) != 0) {
            status = -errno;
        } else if (S_ISDIR(info.st_mode)) {
            status = ChangeDirAndFilesPerm(childFd, depth + 1, directories, files);
            if (status == 0 && fchown(childFd, HUKS_SERVICE_UID, HUKS_SERVICE_UID) != 0) {
                status = -errno;
            }
            if (status == 0 && fchmod(childFd, S_IRWXU) != 0) {
                status = -errno;
            }
            if (status == 0) {
                ++*directories;
            }
        } else if (S_ISREG(info.st_mode) && info.st_nlink == 1) {
            if (fchown(childFd, HUKS_SERVICE_UID, HUKS_SERVICE_UID) != 0 ||
                fchmod(childFd, S_IRUSR | S_IWUSR) != 0) {
                status = -errno;
            } else {
                ++*files;
            }
        } else {
            status = -EINVAL;
        }
        if (close(childFd) != 0 && status == 0) {
            status = -errno;
        }
        if (status != 0) {
            break;
        }
    }
    if (closedir(directory) != 0 && status == 0) {
        status = -errno;
    }
    return status;
}

int main(void)
{
    uint64_t directories = 0;
    uint64_t files = 0;
    int rootFd = open("/data/data/huks_service", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int status = rootFd < 0 ? -errno : ChangeDirAndFilesPerm(rootFd, 0, &directories, &files);
    if (rootFd >= 0 && close(rootFd) != 0 && status == 0) {
        status = -errno;
    }
    /* Init sends stdout to /dev/null. Log actual completion without key aliases. */
    char message[192];
    int length = snprintf(message, sizeof(message),
        "HUKS_COMPATIBILITY pid=%ld uid=%ld status=%d directories=%llu files=%llu\n",
        (long)getpid(), (long)geteuid(), status, (unsigned long long)directories, (unsigned long long)files);
    if (length > 0 && (size_t)length < sizeof(message)) {
        (void)fputs(message, stdout);
        int logFd = open("/dev/kmsg", O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
        if (logFd >= 0) {
            (void)dprintf(logFd, "<6>%s", message);
            (void)close(logFd);
        }
    }
    return status == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
