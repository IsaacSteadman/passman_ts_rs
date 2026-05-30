use std::{
    cell::UnsafeCell,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore, SemaphorePermit};

#[repr(C)]
#[derive(Debug)]
pub struct UrDwLock<T> {
    sema: Semaphore,
    upg: AtomicBool,
    data: UnsafeCell<T>,
}

#[derive(Debug)]
pub struct UrDwLockReadGuard<'a, T> {
    data: *const T,
    par_ref: &'a UrDwLock<T>,
    permit: SemaphorePermit<'a>,
}

#[derive(Debug)]
pub struct UrDwLockWriteGuard<'a, T> {
    data: *mut T,
    par_ref: &'a UrDwLock<T>,
    permit: SemaphorePermit<'a>,
}

#[derive(Debug)]
pub struct UrDwLockReadOwnedGuard<T> {
    data: *const T,
    par_ref: Arc<UrDwLock<T>>,
    permit: OwnedSemaphorePermit,
}

#[derive(Debug)]
pub struct UrDwLockWriteOwnedGuard<T> {
    data: *mut T,
    par_ref: Arc<UrDwLock<T>>,
    permit: OwnedSemaphorePermit,
}

const fn const_min(a: u32, b: usize) -> u32 {
    if a as usize > b { b as u32 } else { a }
}

impl<T> UrDwLock<T> {
    pub const MAX_PERMITS: u32 = const_min(u32::MAX, Semaphore::MAX_PERMITS);
    pub fn new(data: T) -> Self {
        UrDwLock {
            sema: Semaphore::new(Self::MAX_PERMITS as usize),
            upg: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }
    pub async fn read<'a>(&'a self) -> Result<UrDwLockReadGuard<'a, T>, AcquireError> {
        let permit = self.sema.acquire().await?;
        Ok(UrDwLockReadGuard {
            par_ref: self,
            permit,
            data: self.data.get(),
        })
    }
    fn get_sema_arc(self: Arc<Self>) -> Arc<Semaphore> {
        unsafe { std::mem::transmute::<Arc<Self>, Arc<Semaphore>>(self) }
    }
    pub async fn read_owned(self: Arc<Self>) -> Result<UrDwLockReadOwnedGuard<T>, AcquireError> {
        let permit = self.clone().get_sema_arc().acquire_owned().await?;
        Ok(UrDwLockReadOwnedGuard {
            data: self.data.get(),
            par_ref: self,
            permit,
        })
    }
    pub async fn write<'a>(&'a self) -> Result<UrDwLockWriteGuard<'a, T>, AcquireError> {
        let permit = self.sema.acquire_many(Self::MAX_PERMITS).await?;
        Ok(UrDwLockWriteGuard {
            par_ref: self,
            permit,
            data: self.data.get(),
        })
    }
    pub async fn write_owned(self: Arc<Self>) -> Result<UrDwLockWriteOwnedGuard<T>, AcquireError> {
        let permit = self
            .clone()
            .get_sema_arc()
            .acquire_many_owned(Self::MAX_PERMITS)
            .await?;
        Ok(UrDwLockWriteOwnedGuard {
            data: self.data.get(),
            par_ref: self,
            permit,
        })
    }
}

#[derive(Debug)]
pub enum UpgradeError {
    AcquireError(AcquireError),
    AlreadyUpgrading,
}

struct UpgGuard<'a> {
    b: &'a AtomicBool,
}

impl<'a> Drop for UpgGuard<'a> {
    fn drop(&mut self) {
        self.b.store(false, Ordering::Release);
    }
}

impl<'a, T> UrDwLockReadGuard<'a, T> {
    pub async fn upgrade(mut self) -> Result<UrDwLockWriteGuard<'a, T>, (UpgradeError, Self)> {
        if self
            .par_ref
            .upg
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err((UpgradeError::AlreadyUpgrading, self));
        }

        let acq_res = {
            let _guard = UpgGuard {
                b: &self.par_ref.upg,
            };
            self.par_ref
                .sema
                .acquire_many(UrDwLock::<T>::MAX_PERMITS - 1)
                .await
        };
        let permit = match acq_res {
            Err(e) => return Err((UpgradeError::AcquireError(e), self)),
            Ok(o) => o,
        };
        self.permit.merge(permit);
        Ok(UrDwLockWriteGuard {
            permit: self.permit,
            par_ref: self.par_ref,
            data: self.par_ref.data.get(),
        })
    }
}

impl<'a, T> AsRef<T> for UrDwLockReadGuard<'a, T> {
    fn as_ref(&self) -> &T {
        unsafe { &*self.par_ref.data.get() }
    }
}

impl<T> std::ops::Deref for UrDwLockReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.data }
    }
}

impl<T> UrDwLockReadOwnedGuard<T> {
    pub async fn upgrade(mut self) -> Result<UrDwLockWriteOwnedGuard<T>, (UpgradeError, Self)> {
        if self
            .par_ref
            .upg
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err((UpgradeError::AlreadyUpgrading, self));
        }

        let acq_res = {
            let _guard = UpgGuard {
                b: &self.par_ref.upg,
            };
            self.par_ref
                .clone()
                .get_sema_arc()
                .acquire_many_owned(UrDwLock::<T>::MAX_PERMITS - 1)
                .await
        };
        let permit = match acq_res {
            Err(e) => return Err((UpgradeError::AcquireError(e), self)),
            Ok(o) => o,
        };
        self.permit.merge(permit);
        Ok(UrDwLockWriteOwnedGuard {
            data: self.par_ref.data.get(),
            permit: self.permit,
            par_ref: self.par_ref,
        })
    }
}

impl<T> AsRef<T> for UrDwLockReadOwnedGuard<T> {
    fn as_ref(&self) -> &T {
        unsafe { &*self.par_ref.data.get() }
    }
}

impl<T> std::ops::Deref for UrDwLockReadOwnedGuard<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.data }
    }
}

impl<'a, T> UrDwLockWriteGuard<'a, T> {
    pub fn downgrade(mut self) -> UrDwLockReadGuard<'a, T> {
        let _ = self.permit.split(self.permit.num_permits() - 1);
        UrDwLockReadGuard {
            permit: self.permit,
            par_ref: self.par_ref,
            data: self.data,
        }
    }
}

impl<'a, T> AsMut<T> for UrDwLockWriteGuard<'a, T> {
    fn as_mut(&mut self) -> &mut T {
        unsafe { &mut *self.data }
    }
}

impl<T> std::ops::Deref for UrDwLockWriteGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.data }
    }
}

impl<T> std::ops::DerefMut for UrDwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.data }
    }
}

impl<T> UrDwLockWriteOwnedGuard<T> {
    pub fn downgrade(mut self) -> UrDwLockReadOwnedGuard<T> {
        let _ = self.permit.split(self.permit.num_permits() - 1);
        UrDwLockReadOwnedGuard {
            permit: self.permit,
            par_ref: self.par_ref,
            data: self.data,
        }
    }
}

impl<T> AsMut<T> for UrDwLockWriteOwnedGuard<T> {
    fn as_mut(&mut self) -> &mut T {
        unsafe { &mut *self.data }
    }
}

impl<T> std::ops::Deref for UrDwLockWriteOwnedGuard<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.data }
    }
}

impl<T> std::ops::DerefMut for UrDwLockWriteOwnedGuard<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.data }
    }
}

unsafe impl<T: Send> Send for UrDwLock<T> {}
unsafe impl<T: Send + Sync> Sync for UrDwLock<T> {}
unsafe impl<T: Send + Sync> Send for UrDwLockReadOwnedGuard<T> {}
unsafe impl<T: Send + Sync> Send for UrDwLockWriteOwnedGuard<T> {}
