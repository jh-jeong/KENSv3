//
// Created by biscuit on 16. 11. 12.
//

#ifndef KENSV3_BUFFER_HPP
#define KENSV3_BUFFER_HPP

#include <algorithm> // for std::min

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
    size_t read(char *data, size_t bytes, int offset);
    size_t pop(char *data, size_t bytes);

private:
    size_t beg_index_, end_index_, size_, capacity_;
    char *data_;
};

#endif //KENSV3_BUFFER_HPP
