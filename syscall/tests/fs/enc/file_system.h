// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _file_system_h
#define _file_system_h

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openenclave/bits/fs.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syscall/device.h>
#include <unistd.h>

class oe_fd_file_system
{
  public:
    typedef int file_handle;
    typedef DIR* dir_handle;
    typedef struct stat stat_type;
    typedef struct dirent dirent_type;

    static constexpr file_handle invalid_file_handle = -1;
    static constexpr dir_handle invalid_dir_handle = nullptr;

    oe_fd_file_system(void)
    {
    }

    file_handle open(const char* pathname, int flags, mode_t mode)
    {
        return (file_handle)::open(pathname, flags, mode);
    }

    ssize_t write(file_handle file, const void* buf, size_t count)
    {
        return ::write(file, buf, count);
    }

    ssize_t read(file_handle file, void* buf, size_t count)
    {
        return ::read(file, buf, count);
    }

    off_t lseek(file_handle file, off_t offset, int whence)
    {
        return ::lseek(file, offset, whence);
    }

    int close(file_handle file)
    {
        return ::close(file);
    }

    dir_handle opendir(const char* name)
    {
        return (dir_handle)::opendir(name);
    }

    struct dirent* readdir(dir_handle dir)
    {
        return ::readdir(dir);
    }

    void rewinddir(dir_handle dir)
    {
        ::rewinddir(dir);
    }

    int closedir(dir_handle dir)
    {
        return ::closedir(dir);
    }

    int unlink(const char* pathname)
    {
        return ::unlink(pathname);
    }

    int link(const char* oldpath, const char* newpath)
    {
        return ::link(oldpath, newpath);
    }

    int rename(const char* oldpath, const char* newpath)
    {
        return ::rename(oldpath, newpath);
    }

    int mkdir(const char* pathname, mode_t mode)
    {
        return oe_mkdir(pathname, mode);
    }

    int rmdir(const char* pathname)
    {
        return ::rmdir(pathname);
    }

    int stat(const char* pathname, struct stat* buf)
    {
        return ::stat(pathname, buf);
    }

    int truncate(const char* path, off_t length)
    {
        return ::truncate(path, length);
    }

  private:
};

class oe_fd_hostfs_file_system : public oe_fd_file_system
{
  public:
    oe_fd_hostfs_file_system()
    {
        OE_TEST(mount("/", "/", OE_DEVICE_NAME_HOST_FILE_SYSTEM, 0, NULL) == 0);
    }

    ~oe_fd_hostfs_file_system()
    {
        OE_TEST(::umount("/") == 0);
    }
};

#if defined(TEST_SGXFS)
class oe_fd_sgxfs_file_system : public oe_fd_file_system
{
  public:
    oe_fd_sgxfs_file_system()
    {
        OE_TEST(oe_load_module_sgx_file_system() == OE_OK);
        OE_TEST(
            oe_mount("/", "/", OE_DEVICE_NAME_SGX_FILE_SYSTEM, 0, NULL) == 0);
    }

    ~oe_fd_sgxfs_file_system()
    {
        OE_TEST(oe_umount("/") == 0);
    }
};
#endif // TEST_SGXFS

class fd_file_system
{
  public:
    typedef int file_handle;
    typedef DIR* dir_handle;
    typedef struct stat stat_type;
    typedef struct dirent dirent_type;

    static constexpr file_handle invalid_file_handle = -1;
    static constexpr dir_handle invalid_dir_handle = nullptr;

    fd_file_system(void)
    {
    }

    file_handle open(const char* pathname, int flags, mode_t mode)
    {
        return (file_handle)::open(pathname, flags, mode);
    }

    ssize_t write(file_handle file, const void* buf, size_t count)
    {
        return ::write(file, buf, count);
    }

    ssize_t read(file_handle file, void* buf, size_t count)
    {
        return ::read(file, buf, count);
    }

    off_t lseek(file_handle file, off_t offset, int whence)
    {
        return ::lseek(file, offset, whence);
    }

    int close(file_handle file)
    {
        return ::close(file);
    }

    dir_handle opendir(const char* name)
    {
        return (dir_handle)::opendir(name);
    }

    struct dirent* readdir(dir_handle dir)
    {
        return ::readdir(dir);
    }

    void rewinddir(dir_handle dir)
    {
        ::rewinddir(dir);
    }

    int closedir(dir_handle dir)
    {
        return ::closedir(dir);
    }

    int unlink(const char* pathname)
    {
        return ::unlink(pathname);
    }

    int link(const char* oldpath, const char* newpath)
    {
        return ::link(oldpath, newpath);
    }

    int rename(const char* oldpath, const char* newpath)
    {
        return ::rename(oldpath, newpath);
    }

    int mkdir(const char* pathname, mode_t mode)
    {
        return ::mkdir(pathname, mode);
    }

    int rmdir(const char* pathname)
    {
        return ::rmdir(pathname);
    }

    int stat(const char* pathname, struct stat* buf)
    {
        return ::stat(pathname, (struct stat*)buf);
    }

    int truncate(const char* path, off_t length)
    {
        return ::truncate(path, length);
    }

  private:
};

class fd_hostfs_file_system : public fd_file_system
{
  public:
    fd_hostfs_file_system()
    {
        OE_TEST(
            ::mount("/", "/", OE_DEVICE_NAME_HOST_FILE_SYSTEM, 0, NULL) == 0);
    }

    ~fd_hostfs_file_system()
    {
        OE_TEST(::umount("/") == 0);
    }
};

#if defined(TEST_SGXFS)
class fd_sgxfs_file_system : public fd_file_system
{
  public:
    fd_sgxfs_file_system()
    {
        OE_TEST(oe_load_module_sgx_file_system() == OE_OK);
        OE_TEST(
            oe_mount("/", "/", OE_DEVICE_NAME_SGX_FILE_SYSTEM, 0, NULL) == 0);
    }

    ~fd_sgxfs_file_system()
    {
        OE_TEST(oe_umount("/") == 0);
    }
};
#endif // TEST_SGXFS

class stream_file_system
{
  public:
    typedef FILE* file_handle;
    typedef DIR* dir_handle;
    typedef struct stat stat_type;
    typedef struct dirent dirent_type;

    static constexpr file_handle invalid_file_handle = nullptr;
    static constexpr dir_handle invalid_dir_handle = nullptr;

    stream_file_system(void)
    {
    }

    file_handle open(const char* pathname, int flags, mode_t mode)
    {
        FILE* ret = NULL;
        const char* fopen_mode;

        (void)mode;

        switch ((flags & 0x00000003))
        {
            case O_RDONLY:
            {
                fopen_mode = "r";
                break;
            }
            case O_RDWR:
            {
                if (flags & O_CREAT)
                {
                    if (flags & O_TRUNC)
                    {
                        fopen_mode = "w+";
                    }
                    else if (flags & O_APPEND)
                    {
                        fopen_mode = "a+";
                    }
                    else
                    {
                        errno = EINVAL;
                        goto done;
                    }
                }
                else
                {
                    fopen_mode = "r+";
                }
                break;
            }
            case O_WRONLY:
            {
                if (flags & O_CREAT)
                {
                    if (flags & O_TRUNC)
                    {
                        fopen_mode = "w";
                    }
                    else if (flags & O_APPEND)
                    {
                        fopen_mode = "a";
                    }
                    else
                    {
                        errno = EINVAL;
                        goto done;
                    }
                }
                else
                {
                    fopen_mode = "w";
                }
                break;
            }
            default:
            {
                errno = EINVAL;
                goto done;
            }
        }

        ret = ::fopen(pathname, fopen_mode);

    done:
        return ret;
    }

    ssize_t write(file_handle file, const void* buf, size_t count)
    {
        ssize_t ret = -1;

        if (::fwrite(buf, 1, count, file) != count)
        {
            errno = ::ferror(file);
            goto done;
        }

        ret = (ssize_t)count;

    done:
        return ret;
    }

    ssize_t read(file_handle file, void* buf, size_t count)
    {
        ssize_t ret = -1;
        size_t n;

        if ((n = ::fread(buf, 1, count, file)) == 0)
        {
            if (::feof(file))
            {
                errno = ::ferror(file);
                goto done;
            }
        }

        ret = (ssize_t)n;

    done:
        return ret;
    }

    off_t lseek(file_handle file, off_t offset, int whence)
    {
        off_t ret = -1;

        if (::fseek(file, offset, whence) != 0)
        {
            goto done;
        }

        ret = ::ftell(file);

    done:
        return ret;
    }

    int close(file_handle file)
    {
        return ::fclose(file);
    }

    dir_handle opendir(const char* name)
    {
        return (dir_handle)::opendir(name);
    }

    struct dirent* readdir(dir_handle dir)
    {
        return ::readdir(dir);
    }

    void rewinddir(dir_handle dir)
    {
        ::rewinddir(dir);
    }

    int closedir(dir_handle dir)
    {
        return ::closedir(dir);
    }

    int unlink(const char* pathname)
    {
        return ::unlink(pathname);
    }

    int link(const char* oldpath, const char* newpath)
    {
        return ::link(oldpath, newpath);
    }

    int rename(const char* oldpath, const char* newpath)
    {
        return ::rename(oldpath, newpath);
    }

    int mkdir(const char* pathname, mode_t mode)
    {
        return ::mkdir(pathname, mode);
    }

    int rmdir(const char* pathname)
    {
        return ::rmdir(pathname);
    }

    int stat(const char* pathname, struct stat* buf)
    {
        return ::stat(pathname, buf);
    }

    int truncate(const char* path, off_t length)
    {
        return ::truncate(path, length);
    }

  private:
};

class stream_hostfs_file_system : public stream_file_system
{
  public:
    stream_hostfs_file_system()
    {
        OE_TEST(mount("/", "/", OE_DEVICE_NAME_HOST_FILE_SYSTEM, 0, NULL) == 0);
    }

    ~stream_hostfs_file_system()
    {
        OE_TEST(umount("/") == 0);
    }
};

#if defined(TEST_SGXFS)
class stream_sgxfs_file_system : public stream_file_system
{
  public:
    stream_sgxfs_file_system()
    {
        OE_TEST(oe_load_module_sgx_file_system() == OE_OK);
        OE_TEST(
            oe_mount("/", "/", OE_DEVICE_NAME_SGX_FILE_SYSTEM, 0, NULL) == 0);
    }

    ~stream_sgxfs_file_system()
    {
        OE_TEST(oe_umount("/") == 0);
    }
};
#endif // TEST_SGXFS

#endif /* _file_system_h */
