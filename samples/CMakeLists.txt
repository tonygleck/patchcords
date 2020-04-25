#Licensed under the MIT license. See LICENSE file in the project root for full license information.

#this is CMakeLists.txt for samples. There's nothing here, except redirections to
#individual protocol samples

#usePermissiveRulesForSamplesAndTests()

function(add_sample_directory whatIsBuilding)
    add_subdirectory(${whatIsBuilding})

    set_target_properties(${whatIsBuilding} PROPERTIES FOLDER "Samples")
endfunction()

add_sample_directory(socket_listener)
add_sample_directory(socket_sample)
