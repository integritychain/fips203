use subtle::ConditionallySelectable;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Q;

/// Correctly sized encapsulation key specific to the target security parameter set.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
pub struct EncapsKey<const EK_LEN: usize>(pub(crate) [u8; EK_LEN]);


/// Correctly sized decapsulation key specific to the target security parameter set.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
pub struct DecapsKey<const DK_LEN: usize>(pub(crate) [u8; DK_LEN]);


/// Correctly sized ciphertext specific to the target security parameter set.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
pub struct CipherText<const CT_LEN: usize>(pub(crate) [u8; CT_LEN]);


// While Z is nice, simple and correct, the performance is suboptimal.
// This will be addressed (particularly in matrix operations etc) over,
// the medium-term - potentially as a 256-entry row.

/// Stored as u16, but arithmetic as u32 (so we can multiply/reduce/etc)
#[derive(Clone, Copy, Default)]
pub(crate) struct Z(u16);


#[allow(clippy::inline_always)]
impl Z {
    const M: u64 = 2u64.pow(32) / (Q as u64);

    #[allow(clippy::cast_possible_truncation)]

    pub(crate) fn get_u16(self) -> u16 { self.0 }

    pub(crate) fn get_u32(self) -> u32 { u32::from(self.0) }

    pub(crate) fn set_u16(&mut self, a: u16) { self.0 = a }

    #[inline(always)]
    pub(crate) fn add(self, other: Self) -> Self {
        let sum = self.0.wrapping_add(other.0);
        let (trial, borrow) = sum.overflowing_sub(Q);
        let result = u16::conditional_select(&trial, &sum, u8::from(borrow).into());
        Self(result)
    }

    #[inline(always)]
    pub(crate) fn sub(self, other: Self) -> Self {
        let (diff, borrow) = self.0.overflowing_sub(other.0);
        let result = u16::conditional_select(&diff, &diff.wrapping_add(Q), u8::from(borrow).into());
        Self(result)
    }

    #[inline(always)]
    #[allow(clippy::cast_possible_truncation)] // for diff
    pub(crate) fn mul(self, other: Self) -> Self {
        let prod = u64::from(self.0) * u64::from(other.0);
        let quot = prod * Self::M;
        let quot = quot >> (32);
        let rem = prod - quot * u64::from(Q);
        let (diff, borrow) = (rem as u16).overflowing_sub(Q);
        let result = u16::conditional_select(&diff, &diff.wrapping_add(Q), u8::from(borrow).into());
        Self(result)
    }
}
