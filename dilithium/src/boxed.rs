use alloc::{
	alloc::{alloc_zeroed, handle_alloc_error, Layout},
	boxed::Box,
};
use core::ptr::NonNull;

pub(crate) fn zeroed_box<T>() -> Box<T> {
	let layout = Layout::new::<T>();
	if layout.size() == 0 {
		return unsafe { Box::from_raw(NonNull::dangling().as_ptr()) };
	}
	let ptr = unsafe { alloc_zeroed(layout) as *mut T };
	if ptr.is_null() {
		handle_alloc_error(layout);
	}
	unsafe { Box::from_raw(ptr) }
}
