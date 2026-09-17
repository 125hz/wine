/*  DirectInput joystick backed by the host gamepad slot (Madeira / iOS)
 *
 * Copyright 2026 The Madeira authors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* ==========================================================================
 * WHY THIS FILE EXISTS.
 *
 * A controller reaches Windows here as XInput and nothing else. The app
 * samples a GameController object into a shared struct and win32u publishes it
 * through NtUserCallTwoParam_GetGamepadState (wine/include/ntuser.h), which is
 * what dlls/xinput1_3/main.c reads. Every part of that path is inside one Mach
 * task, so it costs one syscall into a memory read.
 *
 * DirectInput does not use that path. dlls/dinput/joystick_hid.c enumerates
 * joysticks by walking GUID_DEVINTERFACE_HID with setupapi and opening each
 * match with CreateFile — devices that winebus.sys creates. There is no
 * winebus.sys in this port, no driver host to load it into (WoW64 runs drivers
 * 64-bit only and this app ships no services.exe/winedevice.exe), and no HID
 * transport under it. So IDirectInput8::EnumDevices(DI8DEVCLASS_GAMECTRL)
 * returns nothing, and a game that reads its pad through DirectInput — which
 * is most games older than about 2010, and plenty newer ones for their menus —
 * sees no controller at all while XInput-era titles in the same prefix work.
 *
 * WHAT THIS IS. The smallest thing that closes that gap: ONE joystick device
 * synthesised from the same gamepad query, with the object set an XInput pad
 * has when winebus.sys exposes it as HID —
 *
 *   X, Y          left stick
 *   Z, Rz         left and right trigger
 *   Rx, Ry        right stick
 *   POV 0         d-pad, as a 8-way hat
 *   buttons 0..9  A B X Y LB RB Back Start LThumb RThumb
 *
 * — the layout Wine's own bus driver reports for an XInput controller, so a
 * game's built-in "Xbox controller" button map lands on the same objects it
 * would land on under Wine on a desktop.
 *
 * WHY THERE IS NO #ifdef. NtUserGetGamepadState is NtUserCallTwoParam with a
 * code appended to the end of the enum in wine/include/ntuser.h. A win32u that
 * does not implement it falls into the default: arm and returns 0, which is
 * bit-for-bit the same answer as "no pad in that slot". So on a stock Wine
 * this file enumerates nothing, dinput.c falls straight through to the HID
 * path, and behaviour is unchanged. The host device is offered FIRST and HID
 * second, never the other way round: a pad that is already in memory must not
 * have to wait behind a setupapi enumeration that will never find anything.
 *
 * NOT IMPLEMENTED, deliberately: force feedback. The vtbl's effect entries are
 * NULL, caps.dwFlags carries no DIDC_FORCEFEEDBACK, and
 * EnumDevices(DIEDFL_FORCEFEEDBACK) filters this device out on guidFFDriver ==
 * GUID_NULL (dinput.c try_enum_device), which is the correct answer rather
 * than a stub that accepts effects and does nothing.
 * ========================================================================== */

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "winuser.h"
#include "wingdi.h"
#include "winerror.h"
#include "winreg.h"
#include "hidusage.h"
#include "dinput.h"
#include "xinput.h"
/* NtUserCallTwoParam_GetGamepadState and its inline wrapper. win32u.dll is in
 * IMPORTS for dinput (Makefile.in), as it is for xinput1_3. */
#include "ntuser.h"

#include "dinput_private.h"
#include "device_private.h"

/* last, so it only defines the one GUID below */
#include "initguid.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(dinput);

static const struct dinput_device_vtbl ios_joystick_vtbl;

/* A stable instance GUID. Games persist the instance GUID they were bound to
 * and call CreateDevice with it on the next run, so it must not change from
 * session to session — which also means it must not be derived from anything
 * about the pad, since the same pad can be a different GameController object
 * after a re-pair. There is exactly one of these devices, so a constant is
 * both sufficient and the only stable choice. */
DEFINE_GUID( ios_joystick_guid, 0x9e573edc, 0x7734, 0x11d2, 0x8d, 0x4a, 0x23, 0x90, 0x3f, 0xb6, 0xbd, 0xf7 );

/* guidProduct is the PIDVID form: {0000<pid><vid>-0000-0000-0000-504944564944}
 * (device.c dinput_pidvid_guid). There is no USB device under this, so the IDs
 * are ours to choose, and the choice matters in one specific way: a family of
 * DirectInput games filters Microsoft's vendor ID (0x045e) out of their own
 * device enumeration, on the assumption that such a device is already visible
 * through XInput and would otherwise be seen twice. Claiming 0x045e here would
 * make exactly the games this file exists for ignore the device. 0x1209 is the
 * pid.codes vendor ID, allocated for projects with no USB-IF membership, which
 * is what this is. */
#define IOS_JOYSTICK_VID 0x1209
#define IOS_JOYSTICK_PID 0x4d47

/* The four XInput user slots, as in XUSER_MAX_COUNT. Only slot 0 is exposed:
 * see ios_joystick_enum_device. */
#define IOS_JOYSTICK_USER 0

/* Object indices. Their ORDER IS THE WIRE FORMAT of device_state: device.c
 * enum_objects_count/enum_objects_init take dwOfs straight from the instance
 * below and index object_properties[] by the index passed to the callback, so
 * these three things — array order, index, dwOfs — must agree. Values are
 * LONGs packed from offset 0 and buttons are bytes packed after them, which is
 * how joystick_hid.c lays its state out too (value_ofs/button_ofs there). */
enum ios_object_index
{
    IOS_OBJ_X = 0,
    IOS_OBJ_Y,
    IOS_OBJ_Z,
    IOS_OBJ_RX,
    IOS_OBJ_RY,
    IOS_OBJ_RZ,
    IOS_OBJ_POV,
    IOS_OBJ_BUTTON_0,
    IOS_OBJ_COUNT = IOS_OBJ_BUTTON_0 + 10,
};
#define IOS_VALUE_COUNT  (IOS_OBJ_POV + 1)        /* objects stored as LONG */
#define IOS_VALUE_OFS(i) ((i) * sizeof(LONG))
#define IOS_BUTTON_OFS(i) (IOS_VALUE_COUNT * sizeof(LONG) + (i))

struct ios_joystick
{
    struct dinput_device base;
    DWORD user_index;
};

static inline struct ios_joystick *impl_from_IDirectInputDevice8W( IDirectInputDevice8W *iface )
{
    return CONTAINING_RECORD( CONTAINING_RECORD( iface, struct dinput_device, IDirectInputDevice8W_iface ),
                              struct ios_joystick, base );
}

/* TRUE when a pad is connected in that slot and `state` was filled. See
 * xinput1_3/main.c host_pad_state — same call, same reasoning. */
static BOOL host_pad_state( DWORD index, XINPUT_STATE *state )
{
    memset( state, 0, sizeof(*state) );
    if (index >= XUSER_MAX_COUNT) return FALSE;
    return NtUserGetGamepadState( index, NtUserGamepadOp_State, state );
}

/* The object table.
 *
 * It holds a POINTER to each guidType rather than the GUID itself, and the
 * DIDEVICEOBJECTINSTANCEW is assembled from a row on demand. GUID_XAxis and
 * friends are `extern const GUID` from dxguid, so their VALUES are not
 * compile-time constants and a static array of DIDEVICEOBJECTINSTANCEW cannot
 * be initialised with them — their ADDRESSES are. (mouse.c sidesteps this by
 * building its instances in an automatic array on every call; a row plus one
 * stack instance is the same idea without the 10 KB memcpy per enumeration.) */
struct ios_object
{
    const GUID *guid;
    DWORD dwOfs;
    DWORD dwType;
    DWORD dwFlags;
    USAGE usage_page;
    USAGE usage;
    const WCHAR *name;
};

static const struct ios_object ios_objects[IOS_OBJ_COUNT] =
{
#define IOS_AXIS( ofs_index, type_index, guid, usage, name )                                  \
    { guid, IOS_VALUE_OFS( ofs_index ), DIDFT_ABSAXIS | DIDFT_MAKEINSTANCE( type_index ),     \
      DIDOI_ASPECTPOSITION, HID_USAGE_PAGE_GENERIC, usage, name }
    /* The names are the ones joystick_hid.c's object_usage_to_string produces
     * for the same usages, because some games match objects by name. */
    IOS_AXIS( IOS_OBJ_X,  0, &GUID_XAxis,  HID_USAGE_GENERIC_X,  L"X Axis" ),
    IOS_AXIS( IOS_OBJ_Y,  1, &GUID_YAxis,  HID_USAGE_GENERIC_Y,  L"Y Axis" ),
    IOS_AXIS( IOS_OBJ_Z,  2, &GUID_ZAxis,  HID_USAGE_GENERIC_Z,  L"Z Axis" ),
    IOS_AXIS( IOS_OBJ_RX, 3, &GUID_RxAxis, HID_USAGE_GENERIC_RX, L"X Rotation" ),
    IOS_AXIS( IOS_OBJ_RY, 4, &GUID_RyAxis, HID_USAGE_GENERIC_RY, L"Y Rotation" ),
    IOS_AXIS( IOS_OBJ_RZ, 5, &GUID_RzAxis, HID_USAGE_GENERIC_RZ, L"Z Rotation" ),
#undef IOS_AXIS
    { &GUID_POV, IOS_VALUE_OFS( IOS_OBJ_POV ), DIDFT_POV | DIDFT_MAKEINSTANCE( 0 ),
      0, HID_USAGE_PAGE_GENERIC, HID_USAGE_GENERIC_HATSWITCH, L"Hat Switch" },
#define IOS_BUTTON( n, name )                                                                 \
    { &GUID_Button, IOS_BUTTON_OFS( n ), DIDFT_PSHBUTTON | DIDFT_MAKEINSTANCE( n ),           \
      0, HID_USAGE_PAGE_BUTTON, (n) + 1, name }
    IOS_BUTTON( 0, L"Button 0" ), IOS_BUTTON( 1, L"Button 1" ), IOS_BUTTON( 2, L"Button 2" ),
    IOS_BUTTON( 3, L"Button 3" ), IOS_BUTTON( 4, L"Button 4" ), IOS_BUTTON( 5, L"Button 5" ),
    IOS_BUTTON( 6, L"Button 6" ), IOS_BUTTON( 7, L"Button 7" ), IOS_BUTTON( 8, L"Button 8" ),
    IOS_BUTTON( 9, L"Button 9" ),
#undef IOS_BUTTON
};

static void ios_object_instance( const struct ios_object *object, DIDEVICEOBJECTINSTANCEW *instance )
{
    memset( instance, 0, sizeof(*instance) );
    instance->dwSize = sizeof(*instance);
    instance->guidType = *object->guid;
    instance->dwOfs = object->dwOfs;
    instance->dwType = object->dwType;
    instance->dwFlags = object->dwFlags;
    instance->wUsagePage = object->usage_page;
    instance->wUsage = object->usage;
    lstrcpynW( instance->tszName, object->name, MAX_PATH );
}

/* Button order: the one an XInput pad has when winebus.sys reports it as HID,
 * so a game's stock "Xbox controller" mapping lands where it expects. */
static const WORD ios_button_mask[10] =
{
    XINPUT_GAMEPAD_A,
    XINPUT_GAMEPAD_B,
    XINPUT_GAMEPAD_X,
    XINPUT_GAMEPAD_Y,
    XINPUT_GAMEPAD_LEFT_SHOULDER,
    XINPUT_GAMEPAD_RIGHT_SHOULDER,
    XINPUT_GAMEPAD_BACK,
    XINPUT_GAMEPAD_START,
    XINPUT_GAMEPAD_LEFT_THUMB,
    XINPUT_GAMEPAD_RIGHT_THUMB,
};

/* ---------------------------------------------------------------- scaling
 *
 * Same two functions as joystick_hid.c scale_value/scale_axis_value, on the
 * same struct object_properties, so DIPROP_RANGE / DIPROP_DEADZONE /
 * DIPROP_SATURATION behave identically on this device and on a HID one. They
 * are duplicated rather than exported because they are four lines each and
 * exporting them would put a HID-shaped signature (struct hid_value_caps) into
 * a header shared with a device that has no HID under it.
 *
 * The logical range is fixed at 0..65535 for every axis, which is what lets
 * one conversion serve both a SHORT stick and a BYTE trigger. */
#define IOS_LOGICAL_MAX 65535

static LONG ios_scale_value( LONG value, const struct object_properties *properties )
{
    LONG log_min = properties->logical_min, log_max = properties->logical_max;
    LONG phy_min = properties->range_min, phy_max = properties->range_max;

    if (log_min > value || log_max < value) return -1; /* invalid / null value */
    return phy_min + MulDiv( value - log_min, phy_max - phy_min, log_max - log_min );
}

static LONG ios_scale_axis_value( LONG value, const struct object_properties *properties )
{
    LONG log_ctr, log_min = properties->logical_min, log_max = properties->logical_max;
    LONG phy_ctr, phy_min = properties->range_min, phy_max = properties->range_max;

    if (phy_min == 0) phy_ctr = phy_max >> 1;
    else phy_ctr = round( (phy_min + phy_max) / 2.0 );
    if (log_min == 0) log_ctr = log_max >> 1;
    else log_ctr = round( (log_min + log_max) / 2.0 );

    value -= log_ctr;
    if (value <= 0)
    {
        log_max = MulDiv( log_min - log_ctr, properties->deadzone, 10000 );
        log_min = MulDiv( log_min - log_ctr, properties->saturation, 10000 );
        phy_max = phy_ctr;
    }
    else
    {
        log_min = MulDiv( log_max - log_ctr, properties->deadzone, 10000 );
        log_max = MulDiv( log_max - log_ctr, properties->saturation, 10000 );
        phy_min = phy_ctr;
    }

    if (value <= log_min) return phy_min;
    if (value >= log_max) return phy_max;
    return phy_min + MulDiv( value - log_min, phy_max - phy_min, log_max - log_min );
}

/* XInput -> logical. Sticks are SHORT, triggers are BYTE; both become the same
 * unsigned 0..65535 the properties above describe. The Y axes are negated:
 * XInput counts up as positive, DirectInput counts down as positive. */
static LONG ios_logical_stick( SHORT value )
{
    return (LONG)value + 32768;
}

static LONG ios_logical_stick_inverted( SHORT value )
{
    /* -32768 must stay in range after negation, hence the clamp. */
    return IOS_LOGICAL_MAX - ((LONG)value + 32768);
}

static LONG ios_logical_trigger( BYTE value )
{
    return value * 257; /* 0..255 -> 0..65535, exactly */
}

/* The d-pad as a hat: 0..7 clockwise from north, and 8 — outside the logical
 * range — for centred, which ios_scale_value turns into the -1 (0xffffffff)
 * DirectInput uses for "no direction". */
static LONG ios_logical_pov( WORD buttons )
{
    BOOL up    = !!(buttons & XINPUT_GAMEPAD_DPAD_UP);
    BOOL down  = !!(buttons & XINPUT_GAMEPAD_DPAD_DOWN);
    BOOL left  = !!(buttons & XINPUT_GAMEPAD_DPAD_LEFT);
    BOOL right = !!(buttons & XINPUT_GAMEPAD_DPAD_RIGHT);

    /* opposite pairs cancel, as a physical hat cannot report both */
    if (up && down) up = down = FALSE;
    if (left && right) left = right = FALSE;

    if (up && right) return 1;
    if (down && right) return 3;
    if (down && left) return 5;
    if (up && left) return 7;
    if (up) return 0;
    if (right) return 2;
    if (down) return 4;
    if (left) return 6;
    return 8;
}

static void ios_logical_state( const XINPUT_GAMEPAD *pad, LONG values[IOS_VALUE_COUNT], BYTE buttons[10] )
{
    UINT i;

    values[IOS_OBJ_X]   = ios_logical_stick( pad->sThumbLX );
    values[IOS_OBJ_Y]   = ios_logical_stick_inverted( pad->sThumbLY );
    values[IOS_OBJ_Z]   = ios_logical_trigger( pad->bLeftTrigger );
    values[IOS_OBJ_RX]  = ios_logical_stick( pad->sThumbRX );
    values[IOS_OBJ_RY]  = ios_logical_stick_inverted( pad->sThumbRY );
    values[IOS_OBJ_RZ]  = ios_logical_trigger( pad->bRightTrigger );
    values[IOS_OBJ_POV] = ios_logical_pov( pad->wButtons );

    for (i = 0; i < ARRAY_SIZE(ios_button_mask); ++i)
        buttons[i] = (pad->wButtons & ios_button_mask[i]) ? 0x80 : 0x00;
}

/* ---------------------------------------------------------------- device */

HRESULT ios_joystick_enum_device( DWORD type, DWORD flags, DIDEVICEINSTANCEW *instance, DWORD version, int index )
{
    XINPUT_STATE state;
    BOOL override;
    DWORD size;

    TRACE( "type %#lx, flags %#lx, instance %p, version %#lx, index %d\n", type, flags, instance, version, index );

    /* ONE device, always slot 0. Two reasons, both about a phone rather than a
     * desk: the app publishes one pad at a time, and a DirectInput game that
     * finds several game controllers usually presents a device picker, which
     * is a modal dialog nobody can dismiss without the controller the dialog
     * is there to choose. */
    if (index != 0) return DIERR_DEVICENOTREG;
    if (!host_pad_state( IOS_JOYSTICK_USER, &state )) return DIERR_DEVICENOTREG;

    size = instance->dwSize;
    memset( instance, 0, size );
    instance->dwSize = size;
    instance->guidInstance = ios_joystick_guid;
    instance->guidProduct = dinput_pidvid_guid;
    instance->guidProduct.Data1 = MAKELONG( IOS_JOYSTICK_VID, IOS_JOYSTICK_PID );
    instance->guidFFDriver = GUID_NULL;     /* no force feedback: see the header comment */
    if (version >= 0x0800) instance->dwDevType = DI8DEVTYPE_GAMEPAD | (DI8DEVTYPEGAMEPAD_STANDARD << 8);
    else instance->dwDevType = DIDEVTYPE_JOYSTICK | (DIDEVTYPEJOYSTICK_GAMEPAD << 8);
    instance->wUsagePage = HID_USAGE_PAGE_GENERIC;
    instance->wUsage = HID_USAGE_GENERIC_GAMEPAD;
    lstrcpynW( instance->tszInstanceName, L"Gamepad", MAX_PATH );
    lstrcpynW( instance->tszProductName, L"Madeira Gamepad", MAX_PATH );

    /* Honour the same HKCU\Software\Wine\DirectInput\Joysticks disable list
     * the HID path honours, so a title that has to be told to ignore a pad can
     * be told in the usual place. */
    if (device_instance_is_disabled( instance, &override )) return DIERR_DEVICENOTREG;

    return DI_OK;
}

static BOOL ios_try_enum_object( struct dinput_device *impl, const DIPROPHEADER *filter, DWORD flags,
                                 enum_object_callback callback, UINT index,
                                 const DIDEVICEOBJECTINSTANCEW *instance, void *data )
{
    if (flags != DIDFT_ALL && !(flags & DIDFT_GETTYPE( instance->dwType ))) return DIENUM_CONTINUE;

    switch (filter->dwHow)
    {
    case DIPH_DEVICE:
        return callback( impl, index, NULL, instance, data );
    case DIPH_BYOFFSET:
        if (filter->dwObj != instance->dwOfs) return DIENUM_CONTINUE;
        return callback( impl, index, NULL, instance, data );
    case DIPH_BYUSAGE:
        if (filter->dwObj != (DWORD)MAKELONG( instance->wUsage, instance->wUsagePage )) return DIENUM_CONTINUE;
        return callback( impl, index, NULL, instance, data );
    case DIPH_BYID:
        if ((filter->dwObj & 0x00ffffff) != (instance->dwType & 0x00ffffff)) return DIENUM_CONTINUE;
        return callback( impl, index, NULL, instance, data );
    }

    return DIENUM_CONTINUE;
}

static HRESULT ios_joystick_enum_objects( IDirectInputDevice8W *iface, const DIPROPHEADER *filter,
                                          DWORD flags, enum_object_callback callback, void *context )
{
    struct ios_joystick *impl = impl_from_IDirectInputDevice8W( iface );
    DIDEVICEOBJECTINSTANCEW instance;
    DWORD i;
    BOOL ret;

    for (i = 0; i < ARRAY_SIZE(ios_objects); ++i)
    {
        ios_object_instance( ios_objects + i, &instance );
        ret = ios_try_enum_object( &impl->base, filter, flags, callback, i, &instance, context );
        if (ret != DIENUM_CONTINUE) return DIENUM_STOP;
    }

    return DIENUM_CONTINUE;
}

/* Same shape as joystick_hid.c init_object_properties, with the caps a HID
 * descriptor would have carried written out instead of read out. */
static BOOL ios_init_object_properties( struct dinput_device *device, UINT index, struct hid_value_caps *caps,
                                        const DIDEVICEOBJECTINSTANCEW *instance, void *data )
{
    struct object_properties *properties;

    if (index == -1) return DIENUM_STOP;
    properties = device->object_properties + index;

    properties->saturation = 10000;
    properties->deadzone = 0;
    properties->granularity = 1;
    properties->range_min = 0;

    if (instance->dwType & DIDFT_AXIS)
    {
        properties->bit_size = 16;
        properties->logical_min = 0;
        properties->logical_max = IOS_LOGICAL_MAX;
        properties->range_max = 65535;
    }
    else /* the hat */
    {
        properties->bit_size = 8;
        properties->logical_min = 0;
        properties->logical_max = 7;
        /* 36000 - 36000/8: eight positions, the last at 315.00 degrees, which
         * is what joystick_hid.c computes from a hat's logical range. */
        properties->range_max = 36000 - 36000 / 8;
    }

    return DIENUM_CONTINUE;
}

/* Sample the pad into device_state, and queue one event per object that moved.
 *
 * This is the whole "buffered from polling at Poll()/GetDeviceState() time"
 * story: there is no report thread and no read_event, so dinput_main.c's input
 * thread skips this device entirely (it requires both read_event and
 * vtbl->read), and every sample happens on the caller's thread inside
 * dinput_device_Poll — which device.c calls at the top of BOTH GetDeviceState
 * and GetDeviceData. A game that only ever calls GetDeviceState therefore
 * needs no Poll of its own, and a game that uses a buffered device gets its
 * events generated at the moment it asks for them. */
static void ios_joystick_sample( struct ios_joystick *impl, BOOL queue )
{
    IDirectInputDevice8W *iface = &impl->base.IDirectInputDevice8W_iface;
    LONG values[IOS_VALUE_COUNT], value, old_value;
    XINPUT_STATE state;
    BYTE buttons[10];
    DWORD time, seq;
    UINT i;

    if (!host_pad_state( impl->user_index, &state ))
    {
        /* Unplugged. Everything the core does about it keys off status, and
         * GetDeviceState/GetDeviceData/Poll all turn STATUS_UNPLUGGED into
         * DIERR_INPUTLOST — which is the error a game is written to handle by
         * re-Acquiring, so a controller that comes back is picked up again. */
        EnterCriticalSection( &impl->base.crit );
        impl->base.status = STATUS_UNPLUGGED;
        LeaveCriticalSection( &impl->base.crit );
        return;
    }

    ios_logical_state( &state.Gamepad, values, buttons );

    EnterCriticalSection( &impl->base.crit );
    time = GetCurrentTime();
    seq = impl->base.dinput->evsequence++;

    for (i = 0; i < IOS_VALUE_COUNT; ++i)
    {
        const struct object_properties *properties = impl->base.object_properties + i;
        if (ios_objects[i].dwType & DIDFT_AXIS) value = ios_scale_axis_value( values[i], properties );
        else value = ios_scale_value( values[i], properties );

        old_value = *(LONG *)(impl->base.device_state + ios_objects[i].dwOfs);
        *(LONG *)(impl->base.device_state + ios_objects[i].dwOfs) = value;
        if (queue && old_value != value) queue_event( iface, i, value, time, seq );
    }

    for (i = 0; i < ARRAY_SIZE(buttons); ++i)
    {
        UINT index = IOS_OBJ_BUTTON_0 + i;
        BYTE old_button = impl->base.device_state[ios_objects[index].dwOfs];

        impl->base.device_state[ios_objects[index].dwOfs] = buttons[i];
        if (queue && old_button != buttons[i]) queue_event( iface, index, buttons[i], time, seq );
    }

    LeaveCriticalSection( &impl->base.crit );
}

static HRESULT ios_joystick_poll( IDirectInputDevice8W *iface )
{
    struct ios_joystick *impl = impl_from_IDirectInputDevice8W( iface );
    ios_joystick_sample( impl, TRUE );
    return DI_OK;
}

static HRESULT ios_joystick_acquire( IDirectInputDevice8W *iface )
{
    struct ios_joystick *impl = impl_from_IDirectInputDevice8W( iface );
    XINPUT_STATE state;

    if (!host_pad_state( impl->user_index, &state )) return DIERR_INPUTLOST;
    /* Prime device_state without queueing: the buttons a player happens to be
     * holding at Acquire time are state, not events. */
    ios_joystick_sample( impl, FALSE );
    return DI_OK;
}

static HRESULT ios_joystick_unacquire( IDirectInputDevice8W *iface )
{
    return DI_OK;
}

HRESULT ios_joystick_create_device( struct dinput *dinput, const GUID *guid, IDirectInputDevice8W **out )
{
    static const DIPROPHEADER filter =
    {
        .dwSize = sizeof(filter),
        .dwHeaderSize = sizeof(filter),
        .dwHow = DIPH_DEVICE,
    };
    struct ios_joystick *impl;
    HRESULT hr;

    TRACE( "dinput %p, guid %s, out %p\n", dinput, debugstr_guid( guid ), out );

    *out = NULL;
    if (!IsEqualGUID( &ios_joystick_guid, guid )) return DIERR_DEVICENOTREG;

    if (!(impl = calloc( 1, sizeof(*impl) ))) return E_OUTOFMEMORY;
    dinput_device_init( &impl->base, &ios_joystick_vtbl, guid, dinput );
    impl->base.crit.DebugInfo->Spare[0] = (DWORD_PTR)(__FILE__ ": struct ios_joystick*->base.crit");
    impl->user_index = IOS_JOYSTICK_USER;

    if (FAILED(hr = ios_joystick_enum_device( 0, 0, &impl->base.instance, dinput->dwVersion, 0 ))) goto failed;
    impl->base.caps.dwDevType = impl->base.instance.dwDevType;
    /* dinput_device_init already set DIDC_ATTACHED | DIDC_EMULATED
     * (device.c). DIDC_POLLEDDEVICE is the honest answer for a device with no
     * report thread, and the flag games check before calling Poll(). */
    impl->base.caps.dwFlags |= DIDC_POLLEDDEVICE;
    impl->base.caps.dwFirmwareRevision = 100;
    impl->base.caps.dwHardwareRevision = 100;
    impl->base.dwCoopLevel = DISCL_NONEXCLUSIVE | DISCL_BACKGROUND;

    /* counts dwAxes/dwButtons/dwPOVs and builds device_format from the table */
    if (FAILED(hr = dinput_device_init_device_format( &impl->base.IDirectInputDevice8W_iface ))) goto failed;
    ios_joystick_enum_objects( &impl->base.IDirectInputDevice8W_iface, &filter, DIDFT_AXIS | DIDFT_POV,
                               ios_init_object_properties, NULL );

    *out = &impl->base.IDirectInputDevice8W_iface;
    return DI_OK;

failed:
    IDirectInputDevice_Release( &impl->base.IDirectInputDevice8W_iface );
    return hr;
}

static const struct dinput_device_vtbl ios_joystick_vtbl =
{
    NULL,                       /* destroy: nothing owned beyond what the core frees
                                 * (device.c dinput_device_internal_release frees
                                 * object_properties, data_queue, the formats and impl) */
    ios_joystick_poll,
    NULL,                       /* read: no report thread, nothing to read from */
    ios_joystick_acquire,
    ios_joystick_unacquire,
    ios_joystick_enum_objects,
    NULL,                       /* get_property: the core answers every property this device has */
    NULL,                       /* get_effect_info      \                                        */
    NULL,                       /* create_effect         |  no force feedback: the device does   */
    NULL,                       /* send_force_feedback…  |  not claim DIDC_FORCEFEEDBACK and     */
    NULL,                       /* send_device_gain      |  guidFFDriver is GUID_NULL            */
    NULL,                       /* enum_created_effect… /                                        */
};
