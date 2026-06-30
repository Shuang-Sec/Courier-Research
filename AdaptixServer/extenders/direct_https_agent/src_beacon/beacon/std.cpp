// 文件作用：轻量级容器实现：在不依赖标准库的情况下提供简单 Vector 和 Map。
#pragma once
#include "ApiLoader.h"

template<typename T>
class Vector {
    T* v_data;
    size_t v_capacity;
    size_t v_size;
    HANDLE v_heapHandle;

    // resize 重新申请更大的数组，并把旧元素复制过去。
    BOOL resize(size_t new_capacity) {
        T* new_data = static_cast<T*>(ApiWin->HeapAlloc(v_heapHandle, 0, new_capacity * sizeof(T)));
        if (!new_data) return false;

        if (v_data) {
            for (size_t i = 0; i < v_size; ++i) {
                new_data[i] = v_data[i];
            }
            ApiWin->HeapFree(v_heapHandle, 0, v_data);
        }

        v_data = new_data;
        v_capacity = new_capacity;
        return true;
    }

    // find 在线性数组里查找元素，找不到就返回当前大小。
    size_t find(const T& value) const {
        for (size_t i = 0; i < v_size; ++i) {
            if (v_data[i] == value) {
                return i;
            }
        }
        return v_size;
    }

public:

    // Vector 构造函数创建一个私有堆，后面所有元素都从这里申请。
    Vector() : v_data(nullptr), v_capacity(0), v_size(0) {
        v_heapHandle = ApiWin->HeapCreate(0, 0, 0);
    }

    // destroy 释放 Vector 内部数组和私有堆。
    void destroy() {
        if (v_data) {
            ApiWin->HeapFree(v_heapHandle, 0, v_data);
        }
        ApiWin->HeapDestroy(v_heapHandle);
    }

    // push_back 把一个新元素追加到数组末尾，空间不够就扩容。
    BOOL push_back(const T& value) {
        if (v_size >= v_capacity) {
            resize(v_capacity == 0 ? 1 : v_capacity * 2);
        }
        if (v_data) {
            v_data[v_size++] = value;
            return true;
        }
        return false;
    }

    // remove 按下标删除元素，并把后面的元素往前挪。
    BOOL remove(size_t index) {
        if (index >= v_size) return false;

        for (size_t i = index; i < v_size - 1; ++i) {
            v_data[i] = v_data[i + 1];
        }
        --v_size;
        return true;
    }

    // pop_back 删除最后一个元素。
    void pop_back() {
        if (v_size > 0)
            --v_size;
    }

    // operator[] 返回指定下标的元素引用，可读可写。
    T& operator[](size_t index) { return v_data[index]; }

    // const operator[] 返回指定下标的只读元素引用。
    const T& operator[](size_t index) const { return v_data[index]; }

    // size 返回当前已经保存的元素数量。
    size_t size() const { return v_size; }

    // capacity 返回当前数组最多能容纳多少元素。
    size_t capacity() const { return v_capacity; }

    // begin 返回第一个元素的位置，方便循环遍历。
    T* begin() { return v_data; }

    // end 返回最后一个元素后面的位置，方便循环遍历。
    T* end() { return v_data + v_size; }
};

template<typename K, typename V>
class Map {

    struct Pair {
        K key;
        V value;
    };

    Pair* m_data;
    size_t m_capacity;
    size_t m_size;
    HANDLE m_heapHandle;

    // resize 重新申请更大的键值对数组，并把旧键值对复制过去。
    BOOL resize(size_t new_capacity) {
        Pair* new_data = static_cast<Pair*>(ApiWin->HeapAlloc(m_heapHandle, 0, new_capacity * sizeof(Pair)));
        if (!new_data) return false;

        if (m_data) {
            for (size_t i = 0; i < m_size; ++i) {
                new_data[i] = m_data[i];
            }
            ApiWin->HeapFree(m_heapHandle, 0, m_data);
        }

        m_data = new_data;
        m_capacity = new_capacity;
        return true;
    }

    // find_index 按 key 查找键值对下标，找不到返回 -1。
    int find_index(const K& key) const {
        for (size_t i = 0; i < m_size; ++i) {
            if (m_data[i].key == key) {
                return static_cast<int>(i);
            }
        }
        return -1;
    }

public:

    // Map 构造函数创建一个私有堆，用来保存键值对数组。
    Map() : m_data(nullptr), m_capacity(0), m_size(0) {
        m_heapHandle = ApiWin->HeapCreate(0, 0, 0);
    }

    // destroy 释放 Map 内部数组和私有堆。
    void destroy() {
        if (m_data) {
            ApiWin->HeapFree(m_heapHandle, 0, m_data);
        }
        ApiWin->HeapDestroy(m_heapHandle);
    }

    class Iterator {
    private:
        Pair* ptr;
    public:
        // Iterator 构造函数保存当前遍历指针。
        Iterator(Pair* p) : ptr(p) {}

        // operator++ 让迭代器移动到下一个键值对。
        Iterator& operator++() { ++ptr; return *this; }

        // operator!= 判断两个迭代器是否指向不同位置。
        BOOL operator!=(const Iterator& other) const { return ptr != other.ptr; }

        // operator* 取出当前迭代器指向的键值对。
        Pair& operator*() { return *ptr; }
    };

    // begin 返回第一个键值对的迭代器。
    Iterator begin() { return Iterator(m_data); }

    // end 返回最后一个键值对后面的位置。
    Iterator end() { return Iterator(m_data + m_size); }

    // insert 新增或更新一个 key 对应的 value。
    BOOL insert(const K& key, const V& value) {
        int index = find_index(key);
        if (index != -1) {
            m_data[index].value = value;
            return true;
        }

        if (m_size >= m_capacity) {
            if (!resize(m_capacity == 0 ? 1 : m_capacity * 2))
                return false;
        }

        m_data[m_size++] = { key, value };
        return true;
    }

    // get 根据 key 取 value，成功时写入输出参数。
    BOOL get(const K& key, V& value) const {
        int index = find_index(key);
        if (index != -1) {
            value = m_data[index].value;
            return true;
        }
        return false;
    }

    // contains 判断 Map 里是否存在某个 key。
    BOOL contains(const K& key) const {
        int index = find_index(key);
        if (index == -1) {
            return false;
        }
        return true;
    }

    // operator[] 根据 key 取 value；不存在时自动插入一个默认值。
    V& operator[](const K& key) {
        int index = find_index(key);
        if (index == -1) {
            insert(key, V{});
            index = find_index(key);
        }
        return m_data[index].value;
    }

    // remove 根据 key 删除一个键值对，并把后面的键值对往前挪。
    BOOL remove(const K& key) {
        int index = find_index(key);
        if (index == -1) return false;

        for (size_t i = index; i < m_size - 1; ++i) {
            m_data[i] = m_data[i + 1];
        }
        --m_size;
        return true;
    }

    // size 返回 Map 当前保存的键值对数量。
    size_t size() const { return m_size; }
};
