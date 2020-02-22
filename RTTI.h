#pragma once
#include <Windows.h>
/*
Some of these are currently unused
But I hope to use them in the future
For Inheritance features
*/

//It is a good as a reference too.

#ifndef RTTI_H
#define RTTI_H


typedef struct _S__TypeDescriptor
{
    uintptr_t pVFTable;
    uintptr_t spare; //Unused
    char name;
} TypeDescriptor;

typedef struct _S__PMD
{
    ptrdiff_t mdisp;
    ptrdiff_t pdisp;
    ptrdiff_t vdisp;
} PMD;

typedef struct _RTTIBaseClassDescriptor {
    TypeDescriptor* pTypeDescriptor;
    unsigned long numContainedBases;
    PMD where;
    unsigned long attributes;
} RTTIBaseClassDescriptor;

#pragma warning (disable:4200)
typedef struct _RTTIBaseClassArray {
    RTTIBaseClassDescriptor* arrayOfBaseClassDescriptors[];
} RTTIBaseClassArray;
#pragma warning (default:4200)

typedef struct _RTTIClassHierarchyDescriptor {
    unsigned long signature;
    unsigned long attributes;
    unsigned long numBaseClasses;
    RTTIBaseClassArray* pBaseClassArray;
} RTTIClassHierarchyDescriptor;

typedef struct _RTTICompleteObjectLocator {
    unsigned long signature;
    unsigned long offset;
    unsigned long cdOffset;
    TypeDescriptor* pTypeDescriptor;
    RTTIClassHierarchyDescriptor* pClassDescriptor;
} RTTICompleteObjectLocator;

#endif