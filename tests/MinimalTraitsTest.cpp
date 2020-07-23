#include <gtest/gtest.h>
#include "jwt-cpp/jwt.h"
#include "picojson/picojson.h"

class minimal_string {
public:
    minimal_string():
        real_value()
    {}
    minimal_string(const minimal_string& base):
        real_value(base.real_value)
    {}
//    minimal_string(const std::string& value):
//        real_value(value)
//    {}
//    explicit minimal_string(const std::string& value):
//        real_value(value)
//    {}
    minimal_string(const std::string& value, int preventCopyConstructor):
        real_value(value)
    {}
//    bool operator==(const minimal_string &other) const
//    {
//        return this->real_value == other.real_value;
//    }
//    bool operator<(const minimal_string &other) const
//    {
//        return this->real_value < other.real_value;
//    }
//    bool operator>(const minimal_string &other) const
//    {
//        return this->real_value > other.real_value;
//    }
    std::string real_value;
};

namespace std
{
//    template<> struct hash<minimal_string>
//    {
//        std::size_t operator()(minimal_string const& s) const noexcept
//        {
//            return std::hash<std::string>()(s.real_value);
//        }
//    };
}

//bool operator==(const minimal_string& lhs, const minimal_string& rhs) noexcept
//{
//    return lhs.real_value == rhs.real_value;
//}

class minimal_object {
public:
    minimal_object():
        real_value()
    {}
    minimal_object(const minimal_object& base):
        real_value(base.real_value)
    {}
    minimal_object(const picojson::object& value):
        real_value(value)
    {}
    picojson::object real_value;
};

class minimal_array {
public:
    minimal_array():
        real_value()
    {}
    minimal_array(const minimal_array& base):
        real_value(base.real_value)
    {}
    minimal_array(const picojson::array& value):
        real_value(value)
    {}
    picojson::array real_value;
};

class minimal_value {
public:
    minimal_value():
        real_value()
    {}
    minimal_value(const minimal_value& base):
        real_value(base.real_value)
    {}
    minimal_value(const minimal_object& base):
        real_value(base.real_value)
    {}
    minimal_value(const minimal_array& base):
        real_value(base.real_value)
    {}
    minimal_value(const minimal_string& base):
        real_value(base.real_value)
    {}
    minimal_value(const double& base):
        real_value(base)
    {}
    minimal_value(const int64_t& base):
        real_value(base)
    {}
    minimal_value(const bool& base):
        real_value(base)
    {}
    minimal_value(const picojson::value& value):
        real_value(value)
    {}
    picojson::value real_value;
};

struct minimal_traits {
    using value_type = minimal_value;
    using object_type = minimal_object;
    using array_type = minimal_array;
    using string_type = minimal_string;
    using number_type = double;
    using integer_type = int64_t;
    using boolean_type = bool;

    static jwt::json::type get_type(const value_type& val) {
        using jwt::json::type;
        if (val.real_value.is<bool>()) return type::boolean;
        if (val.real_value.is<int64_t>()) return type::integer;
        if (val.real_value.is<double>()) return type::number;
        if (val.real_value.is<std::string>()) return type::string;
        if (val.real_value.is<picojson::array>()) return type::array;
        if (val.real_value.is<picojson::object>()) return type::object;

        throw std::logic_error("invalid type");
    }

    static object_type as_object(const value_type& val) {
        if (!val.real_value.is<picojson::object>())
            throw std::bad_cast();
        return minimal_object(val.real_value.get<picojson::object>());
    }

    static string_type as_string(const value_type& val) {
        if (!val.real_value.is<std::string>())
            throw std::bad_cast();
        return minimal_string(val.real_value.get<std::string>(),1);
    }

    static array_type as_array(const value_type& val) {
        if (!val.real_value.is<picojson::array>())
            throw std::bad_cast();
        return minimal_array(val.real_value.get<picojson::array>());
    }

    static int64_t as_int(const value_type& val) {
        if (!val.real_value.is<int64_t>())
            throw std::bad_cast();
        return val.real_value.get<int64_t>();
    }

    static bool as_bool(const value_type& val) {
        if (!val.real_value.is<bool>())
            throw std::bad_cast();
        return val.real_value.get<bool>();
    }

    static double as_number(const value_type& val) {
        if (!val.real_value.is<double>())
            throw std::bad_cast();
        return val.real_value.get<double>();
    }

    static bool parse(value_type& val, const string_type& str){
        return picojson::parse(val.real_value, str.real_value).empty();
    }

    static string_type serialize(const value_type& val){
        return minimal_string(val.real_value.serialize(),1);
    }

    //Functions for json objects
    static int object_count(const object_type& object, const string_type& key) {
        return object.real_value.count(key.real_value);
    }

    static const value_type object_get(const object_type& object, const string_type& key) {
        return object.real_value.at(key.real_value);
    }

    static bool object_set(object_type& object, const string_type& key, const value_type& value) {
        object.real_value[key.real_value] = value.real_value;
        return true;
    }

    static void object_for_each(const object_type& object, std::function<void(const string_type&, const value_type&)> function) {
        for(const auto& value : object.real_value){
            function(minimal_string(value.first,1), value.second);
        }
    }

    //Functions for json strings
    static std::string string_to_std(const string_type& string) {
        return string.real_value;
    }

    static string_type string_from_std(const std::string& string) {
        return minimal_string(string,1);
    }

    static size_t string_hash(const string_type& string){
        return std::hash<std::string>()(string.real_value);
    }

    static bool string_equal(const string_type& string_a, const string_type& string_b){
        return (string_a.real_value == string_b.real_value);
    }

    static bool string_less(const string_type& string_a, const string_type& string_b){
        return 0 < string_a.real_value.compare(string_b.real_value);
    }

    //Functions for json arrays
    template<typename Iterator>
    static const array_type array_construct(Iterator begin, Iterator end){
        picojson::array array;
        while(begin != end){
            minimal_value value(*begin++);
            array.push_back(value.real_value);
        }
        return minimal_array(array);
    }

    static const value_type array_get(const array_type& array, const int index) {
        return array.real_value.at(index);
    }

    static bool array_set(array_type& array, const int index, const value_type& value) {
        array.real_value[index] = value.real_value;
        return true;
    }

    static void array_for_each(const array_type& array, std::function<void(const value_type&)> function) {
        for(const auto& value : array.real_value){
            function(value);
        }
    }
};

TEST(MinimalTraitsTest, BasicClaims) {
    using minimal_claim = jwt::basic_claim<minimal_traits>;

    const auto string = minimal_claim(jwt::default_traits<minimal_traits>::string_from_std("string"));

    const auto array = minimal_claim(jwt::default_traits<minimal_traits>::key_set{jwt::default_traits<minimal_traits>::string_from_std("string"), jwt::default_traits<minimal_traits>::string_from_std("string")});
    const auto integer = minimal_claim((int64_t)159816816);
}

TEST(MinimalTraitsTest, AudienceAsString) {

    minimal_string token = jwt::default_traits<minimal_traits>::string_from_std(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0In0."
        "WZnM3SIiSRHsbO3O7Z2bmIzTJ4EC32HRBKfLznHhrh4");
    auto decoded = jwt::decode<minimal_traits>(token);

    ASSERT_TRUE(decoded.has_algorithm());
    ASSERT_TRUE(decoded.has_type());
    ASSERT_FALSE(decoded.has_content_type());
    ASSERT_FALSE(decoded.has_key_id());
    ASSERT_FALSE(decoded.has_issuer());
    ASSERT_FALSE(decoded.has_subject());
    ASSERT_TRUE(decoded.has_audience());
    ASSERT_FALSE(decoded.has_expires_at());
    ASSERT_FALSE(decoded.has_not_before());
    ASSERT_FALSE(decoded.has_issued_at());
    ASSERT_FALSE(decoded.has_id());

    std::string test = jwt::default_traits<minimal_traits>::string_to_std(decoded.get_algorithm());

    ASSERT_EQ("HS256",  jwt::default_traits<minimal_traits>::string_to_std(decoded.get_algorithm()));
    ASSERT_EQ("JWT", jwt::default_traits<minimal_traits>::string_to_std(decoded.get_type()));
    auto aud = decoded.get_audience();
    ASSERT_EQ(1, aud.size());
    ASSERT_EQ("test", jwt::default_traits<minimal_traits>::string_to_std(*aud.begin()));
}

TEST(MinimalTraitsTest, SetArray) {
    std::vector<int64_t> vect = {
        100,
        20,
        10
    };
    auto token = jwt::create<minimal_traits>()
        .set_payload_claim(minimal_string("test",1), jwt::basic_claim<minimal_traits>(vect.begin(), vect.end()))
        .sign(jwt::algorithm::none{});
    ASSERT_EQ( jwt::default_traits<minimal_traits>::string_to_std(token), "eyJhbGciOiJub25lIn0.eyJ0ZXN0IjpbMTAwLDIwLDEwXX0.");
}

TEST(MinimalTraitsTest, SetObject) {
    std::istringstream iss{"{\"api-x\": [1]}"};
    jwt::basic_claim<minimal_traits> object;
    iss >> object;
    ASSERT_EQ(object.get_type() , jwt::json::type::object);

    auto token = jwt::create<minimal_traits>()
        .set_payload_claim(minimal_string("namespace",1), object)
        .sign(jwt::algorithm::hs256("test"));
    ASSERT_EQ( jwt::default_traits<minimal_traits>::string_to_std(token), "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lc3BhY2UiOnsiYXBpLXgiOlsxXX19.F8I6I2RcSF98bKa0IpIz09fRZtHr1CWnWKx2za-tFQA");
}

TEST(MinimalTraitsTest, VerifyTokenHS256) {
    minimal_string token = jwt::default_traits<minimal_traits>::string_from_std("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE");

    jwt::verifier<jwt::default_clock, minimal_traits> verify = jwt::verify<jwt::default_clock, minimal_traits>({})
        .allow_algorithm(jwt::algorithm::hs256{ "secret" })
        .with_issuer(minimal_string("auth0",1));

    jwt::decoded_jwt<minimal_traits> decoded_token = jwt::decode<minimal_traits>(token);
    verify.verify(decoded_token);
    jwt::decoded_jwt<minimal_traits> decoded_token2 = jwt::decode<minimal_traits>(token);
}
