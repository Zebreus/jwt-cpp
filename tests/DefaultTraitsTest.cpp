#define DISABLE_PICOJSON // We do not need the default picojson implementation here

#include <gtest/gtest.h>
#include "jwt-cpp/jwt.h"
#include "picojson/picojson.h"

using namespace jwt;

// basic picojson traits containing the required methods
struct base_picojson_traits {
    using value_type = picojson::value;
    using object_type = picojson::object;
    using array_type = picojson::array;
    using string_type = std::string;
    using number_type = double;
    using integer_type = int64_t;
    using boolean_type = bool;

    static json::type get_type(const picojson::value& val) {
        using json::type;
        if (val.is<bool>()) return type::boolean;
        if (val.is<int64_t>()) return type::integer;
        if (val.is<double>()) return type::number;
        if (val.is<std::string>()) return type::string;
        if (val.is<picojson::array>()) return type::array;
        if (val.is<picojson::object>()) return type::object;

        throw std::logic_error("invalid type");
    }

    static picojson::object as_object(const picojson::value& val) {
        if (!val.is<picojson::object>())
            throw std::bad_cast();
        return val.get<picojson::object>();
    }

    static std::string as_string(const picojson::value& val) {
        if (!val.is<std::string>())
            throw std::bad_cast();
        return val.get<std::string>();
    }

    static picojson::array as_array(const picojson::value& val) {
        if (!val.is<picojson::array>())
            throw std::bad_cast();
        return val.get<picojson::array>();
    }

    static int64_t as_int(const picojson::value& val) {
        if (!val.is<int64_t>())
            throw std::bad_cast();
        return val.get<int64_t>();
    }

    static bool as_bool(const picojson::value& val) {
        if (!val.is<bool>())
            throw std::bad_cast();
        return val.get<bool>();
    }

    static double as_number(const picojson::value& val) {
        if (!val.is<double>())
            throw std::bad_cast();
        return val.get<double>();
    }

    static bool parse(picojson::value& val, const std::string& str){
        return picojson::parse(val, str).empty();
    }

    static std::string serialize(const picojson::value& val){
        return val.serialize();
    }
};

// picojson traits with all the new methods defined
struct full_picojson_traits : public base_picojson_traits{
    //Functions for json objects
    static int object_count(const object_type& object, const string_type& key) {
        return object.count(key);
    }

    static const value_type object_get(const object_type& object, const string_type& key) {
        return object.at(key);
    }

    static bool object_set(object_type& object, const string_type& key, const value_type& value) {
        object[key] = value;
        return true;
    }

    static void object_for_each(const object_type& object, std::function<void(const string_type&, const value_type&)> function) {
        for(const auto& value : object){
            function(value.first, value.second);
        }
    }

    //Functions for json strings
    static std::string string_to_std(const string_type& string) {
        return string;
    }

    static string_type string_from_std(const std::string& string) {
        return string;
    }

    static size_t string_hash(const string_type& string){
        return std::hash<string_type>()(string);
    }

    static bool string_equal(const string_type& string_a, const string_type& string_b){
        return (string_a == string_b);
    }

    static bool string_less(const string_type& string_a, const string_type& string_b){
        return 0 < string_a.compare(string_b);
    }

    //Functions for json arrays
    template<typename Iterator>
    static const array_type array_construct(Iterator begin, Iterator end){
        return array_type(begin, end);
    }

    static const value_type array_get(const array_type& array, const int index) {
        return array.at(index);
    }

    static bool array_set(array_type& array, const int index, const value_type& value) {
        array[index] = value;
        return true;
    }

    static void array_for_each(const array_type& array, std::function<void(const value_type&)> function) {
        for(const value_type& value : array){
            function(value);
        }
    }
};

// picojson traits without the new methods
struct minimal_picojson_traits : public base_picojson_traits {
};

// picojson traits with wrong method signatures
struct malformed_picojson_traits : public base_picojson_traits{
    //Functions for json objects
    static int object_count(const int& object, const int& key) {
        return 0;
    }

    static const int object_get(const int& object, const int& key) {
        return 0;
    }

    static int object_set(int& object, const int& key, const int& value) {
        return 0;
    }

    static int object_for_each(const int& object, int function) {
        return 0;
    }

    //Functions for json strings
    static int string_to_std(const int& string) {
        return 0;
    }

    static int string_from_std(const int& string) {
        return 0;
    }

    static int string_hash(const int& string){
        return 0;
    }

    static int string_equal(const int& string_a, const int& string_b){
        return 0;
    }

    static int string_less(const int& string_a, const int& string_b){
        return 0;
    }

    //Functions for json arrays
    template<typename Iterator>
    static const int array_construct(int begin, int end){
        return 0;
    }

    static const int array_get(const int& array, const int index) {
        return 0;
    }

    static int array_set(int& array, const int index, const int& value) {
        return 0;
    }

    static int array_for_each(const int& array, int function) {
        return 0;
    }
};

using value_type = typename base_picojson_traits::value_type;
using object_type = typename base_picojson_traits::object_type;
using array_type = typename base_picojson_traits::array_type;
using string_type = typename base_picojson_traits::string_type;
using number_type = typename base_picojson_traits::number_type;
using integer_type = typename base_picojson_traits::integer_type;
using boolean_type = typename base_picojson_traits::boolean_type;

TEST(DefaultTraitsTest, ObjectCountCheckWorks) {
    bool full_result = (jwt::details::has_object_count<full_picojson_traits, object_type, string_type>::value);
    bool minimal_result = (jwt::details::has_object_count<minimal_picojson_traits, object_type, string_type>::value);
    bool malformed_result = (jwt::details::has_object_count<malformed_picojson_traits, object_type, string_type>::value);
    EXPECT_TRUE(full_result) << "has_object_count check failed, but the method exists";
    EXPECT_FALSE(minimal_result) << "has_object_count check succeeded, but the method does not exist";
    EXPECT_FALSE(malformed_result) << "has_object_count check succeeded, but the method has the wrong signature";
}

TEST(DefaultTraitsTest, ObjectGetCheckWorks) {
    bool full_result = (jwt::details::has_object_get<full_picojson_traits, value_type, object_type, string_type>::value);
    bool minimal_result = (jwt::details::has_object_get<minimal_picojson_traits, value_type, object_type, string_type>::value);
    bool malformed_result = (jwt::details::has_object_get<malformed_picojson_traits, value_type, object_type, string_type>::value);
    EXPECT_TRUE(full_result) << "has_object_get check failed, but the method exists";
    EXPECT_FALSE(minimal_result) << "has_object_get check succeeded, but the method does not exist";
    EXPECT_FALSE(malformed_result) << "has_object_get check succeeded, but the method has the wrong signature";
}

TEST(DefaultTraitsTest, ObjectSetCheckWorks) {
    bool full_result = (jwt::details::has_object_set<full_picojson_traits, value_type, object_type, string_type>::value);
    bool minimal_result = (jwt::details::has_object_set<minimal_picojson_traits, value_type, object_type, string_type>::value);
    bool malformed_result = (jwt::details::has_object_set<malformed_picojson_traits, value_type, object_type, string_type>::value);
    EXPECT_TRUE(full_result) << "has_object_set check failed, but the method exists";
    EXPECT_FALSE(minimal_result) << "has_object_set check succeeded, but the method does not exist";
    EXPECT_FALSE(malformed_result) << "has_object_set check succeeded, but the method has the wrong signature";
}

TEST(DefaultTraitsTest, ObjectForEachCheckWorks) {
    bool full_result = (jwt::details::has_object_for_each<full_picojson_traits, value_type, object_type, string_type>::value);
    bool minimal_result = (jwt::details::has_object_for_each<minimal_picojson_traits, value_type, object_type, string_type>::value);
    bool malformed_result = (jwt::details::has_object_for_each<malformed_picojson_traits, value_type, object_type, string_type>::value);
    EXPECT_TRUE(full_result) << "has_object_for_each check failed, but the method exists";
    EXPECT_FALSE(minimal_result) << "has_object_for_each check succeeded, but the method does not exist";
    EXPECT_FALSE(malformed_result) << "has_object_for_each check succeeded, but the method has the wrong signature";
}

TEST(DefaultTraitsTest, StringFromStdCheckWorks) {
    bool full_result = (jwt::details::has_string_from_std<full_picojson_traits, string_type>::value);
    bool minimal_result = (jwt::details::has_string_from_std<minimal_picojson_traits, string_type>::value);
    bool malformed_result = (jwt::details::has_string_from_std<malformed_picojson_traits, string_type>::value);
    EXPECT_TRUE(full_result) << "has_string_from_std check failed, but the method exists";
    EXPECT_FALSE(minimal_result) << "has_string_from_std check succeeded, but the method does not exist";
    EXPECT_FALSE(malformed_result) << "has_string_from_std check succeeded, but the method has the wrong signature";
}

TEST(DefaultTraitsTest, StringToStdCheckWorks) {
    bool full_result = (jwt::details::has_string_to_std<full_picojson_traits, string_type>::value);
    bool minimal_result = (jwt::details::has_string_to_std<minimal_picojson_traits, string_type>::value);
    bool malformed_result = (jwt::details::has_string_to_std<malformed_picojson_traits, string_type>::value);
    EXPECT_TRUE(full_result) << "has_string_to_std check failed, but the method exists";
    EXPECT_FALSE(minimal_result) << "has_string_to_std check succeeded, but the method does not exist";
    EXPECT_FALSE(malformed_result) << "has_string_to_std check succeeded, but the method has the wrong signature";
}

TEST(DefaultTraitsTest, StringHashCheckWorks) {
    bool full_result = (jwt::details::has_string_hash<full_picojson_traits, string_type>::value);
    bool minimal_result = (jwt::details::has_string_hash<minimal_picojson_traits, string_type>::value);
    bool malformed_result = (jwt::details::has_string_hash<malformed_picojson_traits, string_type>::value);
    EXPECT_TRUE(full_result) << "has_string_hash check failed, but the method exists";
    EXPECT_FALSE(minimal_result) << "has_string_hash check succeeded, but the method does not exist";
    EXPECT_FALSE(malformed_result) << "has_string_hash check succeeded, but the method has the wrong signature";
}

TEST(DefaultTraitsTest, StringEqualCheckWorks) {
    bool full_result = (jwt::details::has_string_equal<full_picojson_traits, string_type>::value);
    bool minimal_result = (jwt::details::has_string_equal<minimal_picojson_traits, string_type>::value);
    bool malformed_result = (jwt::details::has_string_equal<malformed_picojson_traits, string_type>::value);
    EXPECT_TRUE(full_result) << "has_string_equal check failed, but the method exists";
    EXPECT_FALSE(minimal_result) << "has_string_equal check succeeded, but the method does not exist";
    EXPECT_FALSE(malformed_result) << "has_string_equal check succeeded, but the method has the wrong signature";
}

TEST(DefaultTraitsTest, StringLessCheckWorks) {
    bool full_result = (jwt::details::has_string_less<full_picojson_traits, string_type>::value);
    bool minimal_result = (jwt::details::has_string_less<minimal_picojson_traits, string_type>::value);
    bool malformed_result = (jwt::details::has_string_less<malformed_picojson_traits, string_type>::value);
    EXPECT_TRUE(full_result) << "has_string_less check failed, but the method exists";
    EXPECT_FALSE(minimal_result) << "has_string_less check succeeded, but the method does not exist";
    EXPECT_FALSE(malformed_result) << "has_string_less check succeeded, but the method has the wrong signature";
}

TEST(DefaultTraitsTest, ArrayConstructCheckWorks) {
    bool full_result = (jwt::details::has_array_construct<full_picojson_traits, array_type, typename std::set<string_type>::iterator>::value);
    bool minimal_result = (jwt::details::has_array_construct<minimal_picojson_traits, array_type, typename std::set<string_type>::iterator>::value);
    bool malformed_result = (jwt::details::has_array_construct<malformed_picojson_traits, array_type, typename std::set<string_type>::iterator>::value);
    EXPECT_TRUE(full_result) << "has_array_construct check failed, but the method exists";
    EXPECT_FALSE(minimal_result) << "has_array_construct check succeeded, but the method does not exist";
    EXPECT_FALSE(malformed_result) << "has_array_construct check succeeded, but the method has the wrong signature";
}

TEST(DefaultTraitsTest, ArraySetCheckWorks) {
    bool full_result = (jwt::details::has_array_set<full_picojson_traits, value_type, array_type>::value);
    bool minimal_result = (jwt::details::has_array_set<minimal_picojson_traits, value_type, array_type>::value);
    bool malformed_result = (jwt::details::has_array_set<malformed_picojson_traits, value_type, array_type>::value);
    EXPECT_TRUE(full_result) << "has_array_set check failed, but the method exists";
    EXPECT_FALSE(minimal_result) << "has_array_set check succeeded, but the method does not exist";
    EXPECT_FALSE(malformed_result) << "has_array_set check succeeded, but the method has the wrong signature";
}

TEST(DefaultTraitsTest, ArrayGetCheckWorks) {
    bool full_result = (jwt::details::has_array_get<full_picojson_traits, value_type, array_type>::value);
    bool minimal_result = (jwt::details::has_array_get<minimal_picojson_traits, value_type, array_type>::value);
    bool malformed_result = (jwt::details::has_array_get<malformed_picojson_traits, value_type, array_type>::value);
    EXPECT_TRUE(full_result) << "has_array_get check failed, but the method exists";
    EXPECT_FALSE(minimal_result) << "has_array_get check succeeded, but the method does not exist";
    EXPECT_FALSE(malformed_result) << "has_array_get check succeeded, but the method has the wrong signature";
}

TEST(DefaultTraitsTest, ArrayForEachCheckWorks) {
    bool full_result = (jwt::details::has_array_for_each<full_picojson_traits, value_type, array_type>::value);
    bool minimal_result = (jwt::details::has_array_for_each<minimal_picojson_traits, value_type, array_type>::value);
    bool malformed_result = (jwt::details::has_array_for_each<malformed_picojson_traits, value_type, array_type>::value);
    EXPECT_TRUE(full_result) << "has_array_for_each check failed, but the method exists";
    EXPECT_FALSE(minimal_result) << "has_array_for_each check succeeded, but the method does not exist";
    EXPECT_FALSE(malformed_result) << "has_array_for_each check succeeded, but the method has the wrong signature";
}
