//
// Created by fesil on 2022/12/2.
//

#ifndef LUAJIT_CDATA_POINTER_H
#define LUAJIT_CDATA_POINTER_H

#include <lua.hpp>
#include <cassert>
#include <type_traits>
#include <optional>
#include <algorithm>

#if defined(__clang__) || defined(__GNUC__)
#define LUAJIT_LIKELY(x)    __builtin_expect(!!(x), 1)
#define LUAJIT_UNLIKELY(x)    __builtin_expect(!!(x), 0)
#else
#define LUAJIT_LIKELY(x)    (x)
#define LUAJIT_UNLIKELY(x)   (x)
#endif

namespace luajit {
    template<typename T>
    constexpr auto is_complex_v = std::is_same_v<T, _Complex float> || std::is_same_v<T, _Complex double> ||
                                  std::is_same_v<T, _Complex long double>;
    constexpr auto ffi_name_sizeof = "sizeof";
    constexpr auto ffi_name_cast = "cast";
    constexpr auto ffi_name_typeof = "typeof";
    constexpr auto LOADED_key = "_LOADED";

    inline void ffi_key(lua_State *L) {
        static char k = 0;
        lua_pushlightuserdata(L, &k);
        assert(lua_islightuserdata(L, -1));
    }


    inline bool init_ffi_api(lua_State *L) {
        auto t = lua_gettop(L);
        ffi_key(L);
        lua_gettable(L, LUA_REGISTRYINDEX);
        if (LUAJIT_UNLIKELY(lua_istable(L, -1))) {
            lua_pop(L, 1);
            assert(lua_gettop(L) == t);
            return true;
        }
        ffi_key(L);
        lua_getfield(L, LUA_REGISTRYINDEX, LOADED_key);
        assert(lua_istable(L, -1));
        lua_getfield(L, -1, "ffi");
        if (LUAJIT_UNLIKELY(lua_isnil(L, -1))) {
            lua_pop(L, 2);
            auto sv = luaL_dostring(L, "return require 'ffi'");
            if (LUAJIT_UNLIKELY(sv != 0)) {
                auto p = lua_tostring(L, -1);
                lua_pop(L, 2);
                assert(lua_gettop(L) == t);
                return false;
            }
        } else {
            lua_remove(L, -2);
        }
        assert(lua_islightuserdata(L, -2));
        assert(lua_istable(L, -1));
        lua_settable(L, LUA_REGISTRYINDEX);
        assert(lua_gettop(L) == t);
        return true;
    }

    inline void push_ffi_function(lua_State *L, const char *name) {
        auto t = lua_gettop(L);
        ffi_key(L);
        lua_gettable(L, LUA_REGISTRYINDEX);
        if (LUAJIT_UNLIKELY(!lua_istable(L, -1))) {
            lua_pop(L, 1);
            init_ffi_api(L);
            ffi_key(L);
            lua_gettable(L, LUA_REGISTRYINDEX);
            assert(lua_istable(L, -1));
        }
        lua_getfield(L, -1, name);
        lua_assert(lua_istable(L, -1));
        lua_remove(L, -2);
        assert(lua_gettop(L) - 1 == t);
    }

    inline size_t lua_cdata_sizeof(lua_State *L, int idx) {
        assert(lua_type(L, idx) == 10);

        auto t = lua_gettop(L);
        // save idx
        lua_pushvalue(L, idx);
        push_ffi_function(L, ffi_name_sizeof);
        lua_pushvalue(L, -2);
        auto rv = lua_pcall(L, 1, 1, 0);
        if (LUAJIT_UNLIKELY(rv != 0)) {
            auto p = lua_tostring(L, -1);
            lua_pop(L, 1);
            assert(lua_gettop(L) == t);
            return 0;
        }
        auto ret = lua_tointeger(L, -1);
        lua_pop(L, 2);
        assert(lua_gettop(L) == t);
        assert(lua_type(L, idx) == 10);
        return ret;
    }

    template<class Tp>
    struct array {
        // types:
        typedef Tp value_type;
        typedef value_type &reference;
        typedef const value_type &const_reference;
        typedef value_type *iterator;
        typedef const value_type *const_iterator;
        typedef value_type *pointer;
        typedef const value_type *const_pointer;
        typedef size_t size_type;
        typedef ptrdiff_t difference_type;
        typedef std::reverse_iterator<iterator> reverse_iterator;
        typedef std::reverse_iterator<const_iterator> const_reverse_iterator;

        Tp *_elems_;
        size_t Size;

        // No explicit construct/copy/destroy for aggregate type
        constexpr void fill(const value_type &_u) {
            std::fill_n(data(), Size, _u);
        }

        constexpr
        void swap(array &_a) noexcept(std::is_nothrow_swappable_v<Tp>) {
            std::swap_ranges(data(), data() + Size, _a.data());
        }

        // iterators:
        constexpr
        iterator begin() noexcept { return iterator(data()); }

        constexpr
        const_iterator begin() const noexcept { return const_iterator(data()); }

        constexpr
        iterator end() noexcept { return iterator(data() + Size); }

        constexpr
        const_iterator end() const noexcept { return const_iterator(data() + Size); }

        constexpr
        reverse_iterator rbegin() noexcept { return reverse_iterator(end()); }

        [[nodiscard]] constexpr
        const_reverse_iterator rbegin() const noexcept { return const_reverse_iterator(end()); }

        constexpr
        reverse_iterator rend() noexcept { return reverse_iterator(begin()); }

        [[nodiscard]] constexpr
        const_reverse_iterator rend() const noexcept { return const_reverse_iterator(begin()); }

        constexpr
        const_iterator cbegin() const noexcept { return begin(); }

        constexpr
        const_iterator cend() const noexcept { return end(); }

        [[nodiscard]] constexpr
        const_reverse_iterator crbegin() const noexcept { return rbegin(); }

        [[nodiscard]] constexpr
        const_reverse_iterator crend() const noexcept { return rend(); }

        // capacity:
        [[nodiscard]] constexpr size_type size() const noexcept { return Size; }

        [[nodiscard]] constexpr size_type max_size() const noexcept { return Size; }

        [[nodiscard]] constexpr bool empty() const noexcept { return Size == 0; }

        // element access:
        _LIBCPP_INLINE_VISIBILITY _LIBCPP_CONSTEXPR_AFTER_CXX14
        reference operator[](size_type _n) noexcept {
            assert(_n < Size);
            return _elems_[_n];
        }

        constexpr
        const_reference operator[](size_type _n) const noexcept {
            assert(_n < Size);
            return _elems_[_n];
        }

        constexpr reference front() noexcept { return (*this)[0]; }

        constexpr const_reference front() const noexcept { return (*this)[0]; }

        constexpr reference back() noexcept { return (*this)[Size - 1]; }

        constexpr const_reference back() const noexcept { return (*this)[Size - 1]; }

        constexpr
        value_type *data() noexcept { return _elems_; }

        constexpr
        const value_type *data() const noexcept { return _elems_; }
    };


    template<typename T>
    decltype(auto) lua_get_from_cdata_unsafe(lua_State *L, int idx) {
        assert(lua_type(L, idx) == 10);
        auto *ptr = lua_topointer(L, idx);
        if constexpr (std::is_reference_v<T>) {
            using decay_T = std::decay_t<T>;
            static_assert(!std::is_reference_v<decay_T>);
            if constexpr (std::is_function_v<std::remove_reference_t<T>>) {
                // handler like ret (&) (args...)
                return (std::add_lvalue_reference_t<decay_T>) *(void **) ptr;
            } else if constexpr (std::is_class_v<decay_T>) {
                return (T) *(decay_T *) ptr;
            } else if constexpr (std::is_pointer_v<decay_T>) {
                return (T) *(void **) ptr;
            } else if constexpr (std::is_enum_v<decay_T>) {
                return T(*(uint32_t *) ptr);
            } else if constexpr (std::is_same_v<decay_T, bool>) {
                return (bool &) (*(bool *) ptr);
            } else if constexpr (std::is_arithmetic_v<decay_T> || is_complex_v<decay_T>) {
                return (T &) (*(decay_T *) ptr);
            } else {
                return ptr;
            }
        } else {
            if constexpr (std::is_class_v<T>) {
                return (T &) *(void **) ptr;
            } else if constexpr (std::is_function_v<T>) {
                return (T *) *(void **) ptr;
            } else if constexpr (std::is_array_v<T>) {
                using t = std::remove_pointer_t<std::decay_t<T>>;
                return luajit::array<t>{(t) ptr, lua_cdata_sizeof(L, -1)/ sizeof(t)};
            } else if constexpr (std::is_pointer_v<T>) {
                return (T) *(void **) ptr;
            } else if constexpr (std::is_enum_v<T>) {
                return T(*(uint32_t *) ptr);
            } else if constexpr (std::is_same_v<T, bool>) {
                return bool(*(bool *) ptr);
            } else if constexpr (std::is_arithmetic_v<T> || is_complex_v<T>) {
                return T(*(T *) ptr);
            } else {
                return ptr;
            }
        }
    }

    template<typename T>
    decltype(auto) lua_get_from_cdata_fast(lua_State *L, int idx) {
        auto sz = lua_cdata_sizeof(L, idx);
        using result_t = std::invoke_result_t<decltype(lua_get_from_cdata_unsafe<T>), lua_State *, int>;
        using r = decltype(std::make_optional(std::declval<result_t>()));
        if constexpr (std::is_function_v<T> || std::is_function_v<std::remove_reference_t<T>> ||
                      std::is_function_v<std::remove_pointer_t<T>>) {
            if (!(sz == 0 || sz == sizeof(void *))) {
                return (r) std::nullopt;
            }
        } else {
            if constexpr (std::is_reference_v<T>) {
                using decay_T = std::decay_t<T>;
                if (sz != sizeof(decay_T)) {
                    return (r) std::nullopt;
                }
            } else {
                if constexpr (std::is_array_v<T>){
                    using t = std::remove_pointer_t<std::decay_t<T>>;
                    if (sz / sizeof(t) == sizeof(t)){
                        return (r) std::nullopt;
                    }
                }else{
                    if (sz != sizeof(T)) {
                        return (r) std::nullopt;
                    }
                }

            }
        }
        return std::make_optional(lua_get_from_cdata_unsafe<T>(L, idx));
    }

    template<typename T>
    decltype(auto) lua_get_from_cdata(lua_State *L, int idx) {

    }
}

#undef LUAJIT_LIKELY
#undef LUAJIT_UNLIKELY
#endif //LEARN_LUAJIT_CDATA_H
