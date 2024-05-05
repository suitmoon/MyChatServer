cmake_minimum_required (VERSION 3.0) #要求cmake最低的版本号
project (chatserver) # 定义当前工程名字
set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -g)

#配置最终的可执行文件输出的路径
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
#配置头文件的搜索路径
include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/include/server)
include_directories(${PROJECT_SOURCE_DIR}/include/server/db)
include_directories(${PROJECT_SOURCE_DIR}/thirdparty)
include_directories(${PROJECT_SOURCE_DIR}/include/server/model)
include_directories(${PROJECT_SOURCE_DIR}/include/server/redis)
link_directories(/usr/lib64/mysql)
# 寻找OpenSSL库
find_package(OpenSSL REQUIRED)

# 链接OpenSSL库
link_libraries(OpenSSL::Crypto)


#指定搜索的子目录
#add_subdirectory(testmuduo src)
add_subdirectory(src)

