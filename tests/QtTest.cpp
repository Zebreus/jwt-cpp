#define DISABLE_PICOJSON // Make sure JWT compiles with this flag

#include <gtest/gtest.h>
#include <QString>
#include <QJsonValue>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>
#include "jwt-cpp/jwt.h"

struct qt_traits {
    // Type Specifications
    using value_type = QJsonValue; // The generic "value type" implementation, most libraries have one
    using object_type = QJsonObject; // The "map type" string to value
    using array_type = QJsonArray; // The "list type" array of values
    using string_type = QString; // The "list of chars", must be a narrow char
    using number_type = double; // The "percision type"
    using integer_type = int; // The "integral type"
    using boolean_type = bool; // The "boolean type"

    // Translation between the implementation notion of type, to the jwt::json::type equivilant
    static jwt::json::type get_type(const value_type &val) {
        using jwt::json::type;
        switch(val.type()){
        case QJsonValue::Type::Bool:
            return type::boolean;
        case QJsonValue::Type::Double:
            return type::number;
        case QJsonValue::Type::String:
            return type::string;
        case QJsonValue::Type::Array:
            return type::array;
        case QJsonValue::Type::Object:
            return type::object;
        case QJsonValue::Type::Null:
        case QJsonValue::Type::Undefined:
            break;
//          return type::boolean;
        }

        throw std::logic_error("invalid type");
    }

    // Conversion from generic value to specific type
    static object_type as_object(const value_type &val){
        if(val.isObject()){
            return val.toObject();
        }else{
            throw std::bad_cast();
        }
    }
    static array_type as_array(const value_type &val){
        if(val.isArray()){
            return val.toArray();
        }else{
            throw std::bad_cast();
        }
    }
    static string_type as_string(const value_type &val){
        if(val.isString()){
            return val.toString();
        }else{
            throw std::bad_cast();
        }
    }
    static number_type as_number(const value_type &val){
        if(val.isDouble()){
            return val.toDouble();
        }else{
            throw std::bad_cast();
        }
    }
    static integer_type as_int(const value_type &val){
        if(val.isDouble()){
            return val.toInt();
        }else{
            throw std::bad_cast();
        }
    }
    static boolean_type as_bool(const value_type &val){
        if(val.isBool()){
            return val.toBool();
        }else{
            throw std::bad_cast();
        }
    }

    // serilization and parsing
    static bool parse(value_type &val, string_type str){
        QJsonValue result = QJsonValue(QJsonValue::Type::Undefined);;
        QJsonDocument document = QJsonDocument::fromJson(str.toUtf8());

        if(document.isObject()){
            result = document.object();
        }else if(document.isArray()){
            result = document.array();
        }else if(document.isEmpty()){
            result = QJsonValue(QJsonValue::Type::Undefined);
        }else{
            QString arrayString = QString("[%1]").arg(str);
            document = QJsonDocument::fromJson(arrayString.toUtf8());
            if(document.isArray() && document.array().size() == 1){
                QJsonValue value = document.array()[0];
                if(value.isString() || value.isDouble() || value.isBool() ){
                    result = value;
                }
            }
        }

        val.swap(result);
        return !val.isUndefined();
    }

    static string_type serialize(const value_type &val){
        QString result = "";

        switch(val.type()){
        case QJsonValue::Type::Bool:
            if(val.toBool()){
                result = "true";
            }else{
                result = "false";
            }
            break;
        case QJsonValue::Type::Double:
            result = QString::number(val.toDouble());
            break;
        case QJsonValue::Type::String :
            result = val.toString();
            break;
        case QJsonValue::Type::Array :
            {
                QJsonDocument arrayDocument(val.toArray());
                result = arrayDocument.toJson(QJsonDocument::Compact);
            }
            break;
        case QJsonValue::Type::Object :
            {
                QJsonDocument objectDocument(val.toObject());
                result = objectDocument.toJson(QJsonDocument::Compact);
            }
            break;
        case QJsonValue::Type::Null:
        case QJsonValue::Type::Undefined:
            result = "";
            break;
        }

        return result;
    }
};

TEST(QtTest, BasicClaims) {
	using qt_claim = jwt::basic_claim<qt_traits>;

	const auto string = nlohmann_claim(QString("string"));
	const auto array = nlohmann_claim(QJsonArray( { 1, 2.2, QString() } ));
	const auto integer = nlohmann_claim(159816816);
}

TEST(QtTest, AudienceAsString) {

	std::string token =
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0In0."
			"WZnM3SIiSRHsbO3O7Z2bmIzTJ4EC32HRBKfLznHhrh4";
	auto decoded = jwt::decode<qt_traits>(token);

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

	ASSERT_EQ("HS256", decoded.get_algorithm());
	ASSERT_EQ("JWT", decoded.get_type());
	auto aud = decoded.get_audience();
	ASSERT_EQ(1, aud.size());
	ASSERT_EQ("test", *aud.begin());
}

TEST(QtTest, SetArray) {
	std::vector<int64_t> vect = {
		100,
		20,
		10
	};
	auto token = jwt::create<qt_traits>()
		.set_payload_claim("test", jwt::basic_claim<qt_traits>(vect.begin(), vect.end()))
		.sign(jwt::algorithm::none{});
	ASSERT_EQ(token, "eyJhbGciOiJub25lIn0.eyJ0ZXN0IjpbMTAwLDIwLDEwXX0.");
}

TEST(QtTest, SetObject) {
	std::istringstream iss{"{\"api-x\": [1]}"};
	jwt::basic_claim<qt_traits> object;
	iss >> object;
	ASSERT_EQ(object.get_type() , jwt::json::type::object);

	auto token = jwt::create<qt_traits>()
		.set_payload_claim("namespace", object)
		.sign(jwt::algorithm::hs256("test"));
	ASSERT_EQ(token, "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lc3BhY2UiOnsiYXBpLXgiOlsxXX19.F8I6I2RcSF98bKa0IpIz09fRZtHr1CWnWKx2za-tFQA");
}

TEST(QtTest, VerifyTokenHS256) {
	std::string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";

	auto verify = jwt::verify<jwt::default_clock, qt_traits>({})
		.allow_algorithm(jwt::algorithm::hs256{ "secret" })
		.with_issuer("auth0");

	auto decoded_token = jwt::decode<qt_traits>(token);
	verify.verify(decoded_token);
}
