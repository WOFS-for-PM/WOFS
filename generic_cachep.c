/*
 * WOFS Generic Cache pool Helper.
 *
 * Copyright 2022-2023 Regents of the University of Harbin Institute of Technology, Shenzhen
 * Computer science and technology, Yanqi Pan <deadpoolmine@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "wofs.h"

DEFINE_GENERIC_CACHEP(obj_ref_inode);
DEFINE_GENERIC_CACHEP(obj_ref_data);
DEFINE_GENERIC_CACHEP(obj_ref_attr);
DEFINE_GENERIC_CACHEP(obj_ref_dentry);
DEFINE_GENERIC_CACHEP(claim_req);

DEFINE_GENERIC_CACHEP(wofs_range_node);
DEFINE_GENERIC_CACHEP(wofs_dentry_info);
DEFINE_GENERIC_CACHEP(wofs_inode_info_header);

DEFINE_GENERIC_CACHEP(tl_node);
