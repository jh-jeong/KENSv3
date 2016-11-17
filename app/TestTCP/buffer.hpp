//
// Created by biscuit on 16. 11. 12.
//

#ifndef KENSV3_BUFFER_HPP
#define KENSV3_BUFFER_HPP

#include <algorithm> // for std::min
#include <unordered_map>

#define ICBUF_MAX 10

class CircularBuffer
{
public:
    CircularBuffer(size_t capacity);
    ~CircularBuffer();

    size_t size() const { return size_; }
    size_t capacity() const { return capacity_; }
    // Return number of bytes written.
    size_t write(const char *data, size_t bytes);
    // Return number of bytes read.
    size_t read(char *data, size_t bytes, size_t offset);
    void pop(size_t bytes);

private:
    size_t beg_index_, end_index_, size_, capacity_;
    char *data_;
};

class IndexedCacheBuffer
{
public:
    IndexedCacheBuffer(size_t capacity);
    ~IndexedCacheBuffer();

    size_t size() const { return size_; }
    size_t capacity() const { return capacity_; }

    bool regCache(uint32_t index, const char *data, size_t bytes);
    uint32_t moveCache(uint32_t index);
    // Return number of bytes read.
    size_t read(char *data, size_t bytes);
    bool write(const char *data, size_t bytes);

private:
    typedef std::pair<char *, size_t> loc_buf;

    size_t beg_index_, end_index_, size_, capacity_;
    char *data_;
    std::unordered_map<uint32_t, loc_buf> index_loc_;
};

#endif //KENSV3_BUFFER_HPP
