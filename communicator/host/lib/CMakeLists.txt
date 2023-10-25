target_sources(mqtt PRIVATE mqtt.c mqtt_pal.c)
target_include_directories(mqtt PUBLIC include)

target_sources(jsmn INTERFACE include/jsmn.h)