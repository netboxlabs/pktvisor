# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

add_library(common INTERFACE)

target_include_directories(common
		INTERFACE
		$<INSTALL_INTERFACE:$<INSTALL_PREFIX>/include>
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
		)

target_compile_features(common INTERFACE cxx_std_11)

target_sources(common
		INTERFACE
		${CMAKE_CURRENT_SOURCE_DIR}/include/common_defs.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/memory_operations.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/MurmurHash3.h
		${CMAKE_CURRENT_SOURCE_DIR}/include/serde.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/count_zeros.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/inv_pow2_table.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/binomial_bounds.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/conditional_back_inserter.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/conditional_forward.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/ceiling_power_of_2.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/kolmogorov_smirnov.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/kolmogorov_smirnov_impl.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/quantiles_sorted_view.hpp
  		${CMAKE_CURRENT_SOURCE_DIR}/include/quantiles_sorted_view_impl.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/optional.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/version.hpp.in
		${CMAKE_CURRENT_SOURCE_DIR}/include/xxhash64.h
		)
