//
// Created by biscuit on 16. 11. 12.
//

#include "buffer.hpp"
#include <cstring>
#include <iostream>

CircularBuffer::CircularBuffer(size_t capacity)
        : beg_index_(0)
        , end_index_(0)
        , size_(0)
        , capacity_(capacity)
{
    data_ = new char[capacity];
}

CircularBuffer::~CircularBuffer()
{
    delete [] data_;
}

size_t CircularBuffer::write(const char *data, size_t bytes)
{
    if (bytes == 0) return 0;

    size_t capacity = capacity_;
    size_t bytes_to_write = std::min(bytes, capacity - size_);

    // Write in a single step
    if (bytes_to_write <= capacity - end_index_)
    {
        memcpy(data_ + end_index_, data, bytes_to_write);
        end_index_ += bytes_to_write;
        if (end_index_ == capacity) end_index_ = 0;
    }
        // Write in two steps
    else
    {
        size_t size_1 = capacity - end_index_;
        memcpy(data_ + end_index_, data, size_1);
        size_t size_2 = bytes_to_write - size_1;
        memcpy(data_, data + size_1, size_2);
        end_index_ = size_2;
    }

    size_ += bytes_to_write;
    return bytes_to_write;
}

size_t CircularBuffer::read(char *data, size_t bytes, size_t offset)
{
    if (bytes == 0) return 0;
    if (size_ <= offset) return 0;

    size_t capacity = capacity_;
    size_t bytes_to_read = std::min(bytes, size_ - offset);
    size_t off_index = (beg_index_ + offset) % capacity;

    // Read in a single step
    if (bytes_to_read <= capacity - off_index)
        memcpy(data, data_ + off_index, bytes_to_read);
    // Read in two steps
    else
    {
        size_t size_1 = capacity - off_index;
        memcpy(data, data_ + off_index, size_1);
        size_t size_2 = bytes_to_read - size_1;
        memcpy(data + size_1, data_, size_2);
    }
    return bytes_to_read;
}

void CircularBuffer::pop(size_t bytes)
{
    if (bytes == 0) return;

    size_t capacity = capacity_;
    size_t bytes_pop = std::min(bytes, size_);
    // Read in a single step
    if (bytes_pop <= capacity - beg_index_)
    {
        beg_index_ += bytes_pop;
        if (beg_index_ == capacity) beg_index_ = 0;
    }
    // Read in two steps
    else
    {
        size_t size_1 = capacity - beg_index_;
        size_t size_2 = bytes_pop - size_1;
        beg_index_ = size_2;
    }
    size_ -= bytes_pop;
}

IndexedCacheBuffer::IndexedCacheBuffer(size_t capacity)
        : beg_index_(0)
        , end_index_(0)
        , size_(0)
        , capacity_(capacity)
{
    data_ = new char[capacity];
}

IndexedCacheBuffer::~IndexedCacheBuffer()
{
    delete [] data_;
}

bool IndexedCacheBuffer::regCache(uint32_t index, const char *data, size_t bytes)
{
    if (index_loc_.count(index))
        return true;
    if (index_loc_.size() == ICBUF_MAX)
        return false;

    char *buf = new char[bytes];
    memcpy(buf, data, bytes);
    index_loc_[index] = {buf, bytes};
    return true;
}

uint32_t IndexedCacheBuffer::moveCache(uint32_t index)
{
    std::unordered_map<uint32_t, loc_buf>::iterator entry;
    entry = index_loc_.find(index);

    if (entry == index_loc_.end())
        return index;

    loc_buf to_write = entry->second;
    char *buf = to_write.first;
    size_t len = to_write.second;
    if (write(buf, len)) {
        index_loc_.erase(index);
        delete [] buf;
        return (index + (uint32_t) len);
    }
    else return index;
}

bool IndexedCacheBuffer::write(const char *data, size_t bytes)
{
    if (bytes == 0) return true;

    size_t capacity = capacity_;

    if (bytes > capacity - size_) return false;

    // Write in a single step
    if (bytes <= capacity - end_index_)
    {
        memcpy(data_ + end_index_, data, bytes);
        end_index_ += bytes;
        if (end_index_ == capacity) end_index_ = 0;
    }
        // Write in two steps
    else
    {
        size_t size_1 = capacity - end_index_;
        memcpy(data_ + end_index_, data, size_1);
        size_t size_2 = bytes - size_1;
        memcpy(data_, data + size_1, size_2);
        end_index_ = size_2;
    }

    size_ += bytes;
    return true;
}

size_t IndexedCacheBuffer::read(char *data, size_t bytes)
{
    if (bytes == 0) return 0;

    size_t capacity = capacity_;
    size_t bytes_to_read = std::min(bytes, size_);

    // Read in a single step
    if (bytes_to_read <= capacity - beg_index_)
    {
        memcpy(data, data_ + beg_index_, bytes_to_read);
        beg_index_ += bytes_to_read;
        if (beg_index_ == capacity) beg_index_ = 0;
    }
    // Read in two steps
    else
    {
        size_t size_1 = capacity - beg_index_;
        memcpy(data, data_ + beg_index_, size_1);
        size_t size_2 = bytes_to_read - size_1;
        memcpy(data + size_1, data_, size_2);
        beg_index_ = size_2;
    }

    size_ -= bytes_to_read;
    return bytes_to_read;
}