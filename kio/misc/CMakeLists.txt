
# for strange kio/foo.h includes
include_directories( BEFORE ${CMAKE_SOURCE_DIR}/kio )

if (NOT EMSCRIPTEN)
    add_subdirectory( ksendbugmail )
endif()
if(NOT WIN32 AND NOT EMSCRIPTEN)
  # arpa/nameser.h
  add_subdirectory( kpac )
endif(NOT WIN32 AND NOT EMSCRIPTEN)
add_subdirectory( kntlm )

########### next target ###############

if (NOT EMSCRIPTEN)
    set(kmailservice_SRCS kmailservice.cpp )


    kde4_add_executable(kmailservice NOGUI ${kmailservice_SRCS})

    target_link_libraries(kmailservice  ${KDE4_KDEUI_LIBS})

    install(TARGETS kmailservice DESTINATION ${LIBEXEC_INSTALL_DIR})
    install(PROGRAMS kmailservice.desktop DESTINATION ${XDG_APPS_INSTALL_DIR})
endif()

########### next target ###############

if (NOT EMSCRIPTEN)
    set(ktelnetservice_SRCS ktelnetservice.cpp )


    kde4_add_executable(ktelnetservice NOGUI ${ktelnetservice_SRCS})

    target_link_libraries(ktelnetservice  ${KDE4_KDEUI_LIBS} )

    install(TARGETS ktelnetservice DESTINATION ${LIBEXEC_INSTALL_DIR} )
    install(PROGRAMS ktelnetservice.desktop DESTINATION ${XDG_APPS_INSTALL_DIR})
endif()

########### install files ###############

install( FILES rtsp.protocol mms.protocol mmst.protocol mmsu.protocol pnm.protocol rtspt.protocol rtspu.protocol  DESTINATION  ${SERVICES_INSTALL_DIR} )

