# for KDE 4.7 we require at least version 0.60
set(SHARED_MIME_INFO_MINIMUM_VERSION "0.60")
find_package(SharedMimeInfo)
macro_log_feature(SHARED_MIME_INFO_FOUND "shared-mime-info" "Allows KDE applications to determine file types" "http://freedesktop.org/wiki/Software/shared-mime-info" TRUE "${SHARED_MIME_INFO_MINIMUM_VERSION}" "")

########### install files ###############
install(FILES kde.xml DESTINATION ${XDG_MIME_INSTALL_DIR})
update_xdg_mimetypes(${XDG_MIME_INSTALL_DIR})
