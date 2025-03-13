#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <atomic>
#include <thread>
#include <unordered_map>
#include <cstring> 
#include <fstream> 

#include "cJSON.h"
#include "Database.h"

namespace AppLayout
{
    class JsonBuilder 
    {
    private:
        cJSON* root;

        cJSON* categories;
        cJSON* subcategories;

        cJSON* current_category;
        cJSON* current_subcategory;
        
        bool has_subcategory;
        
        std::string current_category_name;
        std::string current_subcategory_name;
        
        static const std::string default_sub;

    public:
        JsonBuilder();
        ~JsonBuilder();
        void add_category(const std::string& name);
        void add_subcategory(const std::string& name);
        void add_item(const std::string& command);
        std::string get_json_string() const;
        void save_to_file(const std::string& filename) const;
    };

    class Parser {
    private:
        JsonBuilder builder;
        std::string response;

        static std::string trim(const std::string& str);
        std::string parse_cat(const std::string& line);
        std::string extract_command_name(const std::string& line, std::unordered_map<std::string, std::string>& buttons);
    public:
        Parser();
        void parse_file(const std::string& filename, std::unordered_map<std::string, std::string>& buttons);
        void save_json(const std::string& filename);
        std::string& get_json();
    };
}


#if 0
namespace modules
{
    struct notes
    {
        Database *db;
        cJSON *schema = nullptr;
        const std::string TABLE_NAME = "notes";

        notes();
        ~notes();

        std::string getCurrentTimestamp() 
        {
            auto now = std::chrono::system_clock::now();
            auto time = std::chrono::system_clock::to_time_t(now);
            std::stringstream ss;
            ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
            return ss.str();
        }

        // Validate and sanitize input against schema
        cJSON* validateAgainstSchema(cJSON* input) 
        {
            cJSON* validatedData = cJSON_CreateObject();
            cJSON* schemaField = nullptr;

            // Iterate through schema fields dont care about anything else
            cJSON_ArrayForEach(schemaField, schema) 
            {
                const char* fieldName = schemaField->string;
                FIELD_TYPES fieldType = static_cast<FIELD_TYPES>(schemaField->valuedouble);
                
                cJSON* inputField = cJSON_GetObjectItem(input, fieldName);
                
                // Skip timestamp as it's handled automatically
                if (strcmp(fieldName, "timestamp") == 0) {
                    continue;
                }

                if (!inputField) {
                    cJSON_Delete(validatedData);
                    throw std::runtime_error(std::string("Missing required field: ") + fieldName);
                }

                // Validate and convert based on schema type
                switch (fieldType) {
                    case FIELD_TYPES::TEXT:
                        if (!cJSON_IsString(inputField)) {
                            cJSON_Delete(validatedData);
                            throw std::runtime_error(std::string("Field must be string: ") + fieldName);
                        }
                        cJSON_AddStringToObject(validatedData, fieldName, inputField->valuestring);
                        break;

                    case FIELD_TYPES::INTEGER:
                        if (!cJSON_IsNumber(inputField)) {
                            cJSON_Delete(validatedData);
                            throw std::runtime_error(std::string("Field must be number: ") + fieldName);
                        }
                        cJSON_AddNumberToObject(validatedData, fieldName, inputField->valueint);
                        break;

                    case FIELD_TYPES::REAL:
                        if (!cJSON_IsNumber(inputField)) {
                            cJSON_Delete(validatedData);
                            throw std::runtime_error(std::string("Field must be number: ") + fieldName);
                        }
                        cJSON_AddNumberToObject(validatedData, fieldName, inputField->valuedouble);
                        break;

                    case FIELD_TYPES::BOOLEAN:
                        if (!cJSON_IsBool(inputField)) {
                            cJSON_Delete(validatedData);
                            throw std::runtime_error(std::string("Field must be boolean: ") + fieldName);
                        }
                        cJSON_AddBoolToObject(validatedData, fieldName, cJSON_IsTrue(inputField));
                        break;

                    case FIELD_TYPES::DATETIME:
                        if (!cJSON_IsString(inputField)) {
                            cJSON_Delete(validatedData);
                            throw std::runtime_error(std::string("Field must be string date: ") + fieldName);
                        }
                        cJSON_AddStringToObject(validatedData, fieldName, inputField->valuestring);
                        break;
                }
            }

            // Add timestamp
            cJSON_AddStringToObject(validatedData, "timestamp", getCurrentTimestamp().c_str());
            
            return validatedData;
        }

        void create_new_note(cJSON* noteData) 
        {
            if (!noteData) {
                throw std::runtime_error("Invalid note data");
            }

            cJSON* validatedNote = nullptr;
            try {
                validatedNote = validateAgainstSchema(noteData);
                db->insert(TABLE_NAME, validatedNote);
            } catch (const std::exception& e) {
                if (validatedNote) cJSON_Delete(validatedNote);
                throw std::runtime_error("Failed to create note: " + std::string(e.what()));
            }

            if (validatedNote) cJSON_Delete(validatedNote);
        }

        void edit_note(int note_id, cJSON* noteData) {
            if (!noteData) {
                throw std::runtime_error("Invalid note data");
            }

            cJSON* validatedNote = nullptr;
            try {
                validatedNote = validateAgainstSchema(noteData);
                std::vector<std::string> params = {std::to_string(note_id)};
                db->update(TABLE_NAME, validatedNote, "id = ?", params);
            } catch (const std::exception& e) {
                if (validatedNote) cJSON_Delete(validatedNote);
                throw std::runtime_error("Failed to edit note: " + std::string(e.what()));
            }

            if (validatedNote) cJSON_Delete(validatedNote);
        }

        cJSON* search_notes_by_field(const std::string& fieldName, const std::string& searchTerm) {
            // Verify field exists in schema
            if (!cJSON_HasObjectItem(schema, fieldName.c_str())) {
                throw std::runtime_error("Field " + fieldName + " not found in schema");
            }

            try {
                std::vector<std::string> params = {"%" + searchTerm + "%"};
                return db->select(TABLE_NAME, fieldName + " LIKE ?", params);
            } catch (const std::exception& e) {
                throw std::runtime_error("Failed to search notes: " + std::string(e.what()));
            }
        }

        // Basic operations that don't need schema validation
        void delete_note(int note_id) {
            try {
                std::vector<std::string> params = {std::to_string(note_id)};
                db->delete_record(TABLE_NAME, "id = ?", params);
            } catch (const std::exception& e) {
                throw std::runtime_error("Failed to delete note: " + std::string(e.what()));
            }
        }

        cJSON* get_all_notes() {
            try {
                return db->select(TABLE_NAME, "", {});
            } catch (const std::exception& e) {
                throw std::runtime_error("Failed to get notes: " + std::string(e.what()));
            }
        }

    };

}
#endif