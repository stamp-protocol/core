//! This library provides interfaces and helpers for defining private data in nested structures and
//! stripping that private data out of those structures such that a) the structures retain their
//! shape and b) given the stripped object and a container of private data that was returned from
//! the stripping process, the original object can be reconstructed.
//!
//! The idea behind this is to make it easy to provide public and private "views" of an object (or
//! tree of objects) without having to define multiple structures (ie, `MyObjectPublic`,
//! `MyObjectPrivate`) and instead use a more pallatable `MyObject<Full>` / `MyObject<Public>`
//! syntax. This allows for defining the shape/derives/helpers/etc just once while also informing
//! the type system of which view of the object is needed for various uses.
//!
//! Although this is built in support of the Stamp ecosystem, it is built in a generic way that
//! allows for anyone needing to define data with public/private boundaries to implement it.

pub use private_parts_derive::PrivateParts;
use rasn::{AsnType, Decode, Encode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fmt::Debug;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MergeError {
    /// Private data was expected but not found
    #[error("missing private data")]
    MissingPrivateData,
    /// Private data has a type that doesn't match the field it's being merged into
    #[error("private data has unexpected type")]
    TypeMismatch,
}

/// Marks a type as "private" which allowed converting it to/from `Option`.
pub trait PrivateData {}

/// Allows converting an type into an `Option`. This is mostly useful because our [`Full`] type
/// will return the full type (ie, `Some(T)`) and our [`Public`] type will return `None`, which
/// serializes succinctly.
pub trait AsOption: Sized {
    /// Turn the type into an Option.
    fn into_option(self) -> Option<Self>;

    /// Parse the type from an Option.
    fn try_from_option(value: Option<Self>) -> core::result::Result<Self, ()>;
}

impl AsOption for () {
    fn into_option(self) -> Option<Self> {
        None
    }

    fn try_from_option(value: Option<Self>) -> core::result::Result<Self, ()> {
        match value {
            None => Ok(()),
            _ => Err(()),
        }
    }
}

impl<T: PrivateData> AsOption for T {
    fn into_option(self) -> Option<Self> {
        Some(self)
    }

    fn try_from_option(value: Option<Self>) -> core::result::Result<Self, ()> {
        match value {
            Some(x) => Ok(x),
            _ => Err(()),
        }
    }
}

/// A trait that allows us to define a type that holds private data of an arbitrary type.
/// Implemented by other types that wish to have privacy "modes" (such as [`Full`] or [`Public`])
/// that determine the current view of an object (in this case, public vs private).
///
/// It can be used like so:
///
/// ```
/// use private_parts::{AsOption, PrivateData, PrivacyMode, Full, Public};
/// use rasn::{AsnType, Encode, Decode};
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Clone, Debug, AsnType, Encode, Decode, Serialize, Deserialize)]
/// #[rasn(delegate)]
/// struct Secret([u8; 32]);
///
/// impl PrivateData for Secret {};
///
/// struct Key<M: PrivacyMode> {
///     // public field, present in any mode
///     public: [u8; 32],
///     // private field, will be Secret in Full mode and () in private mode
///     private: M::Private<Secret>,
/// }
///
/// struct Container<M: PrivacyMode> {
///     id: String,
///     key: Key<M>,
/// }
///
/// /// Create a full/private version of the container
/// let container = Container::<Full> {
///     id: "mykey".into(),
///     key: Key::<Full> {
///         public: [0u8; 32],
///         private: Secret([1u8; 32]),
///     },
/// };
///
/// /// Create a public version of the container, which has the exact same shape but no private
/// /// keydata
/// let container_public = Container::<Public> {
///     id: "mykey".into(),
///     key: Key::<Public> {
///         public: [0u8; 32],
///         private: (),
///     },
/// };
/// ```
///
/// To convert between `MyObject<Full>` and `MyObject<Public>`, see [`PrivateParts`].
pub trait PrivacyMode: Clone {
    // NOTE: i DO NOT want to force all these traits into this type, however, as far as I can tell
    // there is no other way to express this unless we force ridiculously convoluted `where:`
    // clauses on each type containing `<M: PrivacyMode>`. If this trait could remain entirely
    // agnostic and there be a way to implement these traits on the *bottom layer* (ie,
    // our `stamp_core::crypto::private::Private` struct) such that the containers don't need to
    // have `where: M: PrivacyMode, M::Private<Sealed>: Clone + Debug + AsnType ...` all the way
    // up, I WOULD BE SO HAPPY. Until someone shows me the way, I shamefully must force these
    // traits into my otherwise pure implementation.
    //
    // A good test case is `tests::constraints()`. A shining example of what could be and a
    // testament to my failure.
    type Private<F: Clone + Debug + AsnType + Encode + Decode + Serialize + DeserializeOwned + AsOption>: Clone
        + Debug
        + AsnType
        + Encode
        + Decode
        + Serialize
        + DeserializeOwned
        + AsOption;
}

/// Used to signify a type has the full, unstripped data available.
#[derive(Clone, Debug, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
pub struct Full;

/// Used to signify a type contains only stripped (ie, public) data.
#[derive(Clone, Debug, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
pub struct Public;

impl PrivacyMode for Full {
    type Private<T: Clone + Debug + AsnType + Encode + Decode + Serialize + DeserializeOwned + AsOption> = T;
}

impl PrivacyMode for Public {
    type Private<T: Clone + Debug + AsnType + Encode + Decode + Serialize + DeserializeOwned + AsOption> = ();
}

/// Defines a set of methods for how a container gets private data added to/removed from it. The
/// values *must* be pushed/popped in FIFO order.
pub trait PrivateDataContainer: Default {
    type Value;

    /// Push a value into this container
    fn push_private(&mut self, val: Self::Value);

    /// Pop a value off this container
    fn pop_private(&mut self) -> Option<Self::Value>;
}

/// Allows splitting an object into its public and private parts and then merging those separate
/// objects back together to create the full original object again.
///
/// This is best used with [`Full`] and [`Public`] in order to convert between public and private
/// representations of a type with no loss of data:
///
/// ```
/// use private_parts::{AsOption, PrivateData, PrivacyMode, Full, Public, PrivateDataContainer, PrivateParts, MergeError};
/// use rasn::{AsnType, Encode, Decode};
/// use serde::{Serialize, Deserialize};
/// use std::collections::VecDeque;
///
/// #[derive(Clone, Debug, AsnType, Encode, Decode, Serialize, Deserialize)]
/// #[rasn(delegate)]
/// struct Secret([u8; 32]);
///
/// impl PrivateData for Secret {}
///
/// #[derive(Debug)]
/// pub enum PrivateValue {
///     Octets32(Secret),
/// }
///
/// struct PrivateContainer<T> {
///     values: VecDeque<T>,
/// }
///
/// impl<T> Default for PrivateContainer<T> {
///     fn default() -> Self {
///         Self { values: VecDeque::new() }
///     }
/// }
///
/// impl<T> PrivateDataContainer for PrivateContainer<T> {
///     type Value = T;
///     fn push_private(&mut self, val: Self::Value) {
///         self.values.push_front(val);
///     }
///     fn pop_private(&mut self) -> Option<Self::Value> {
///         self.values.pop_back()
///     }
/// }
///
/// struct Key<M: PrivacyMode> {
///     public: [u8; 32],
///     private: M::Private<Secret>,
/// }
///
/// impl PrivateParts for Key<Full> {
///     type PublicView = Key<Public>;
///     type PrivateData = PrivateContainer<PrivateValue>;
///     type MergeError = MergeError;
///
///     fn strip(self) -> (Self::PublicView, Self::PrivateData) {
///         let Self { public, private } = self;
///         let public = Self::PublicView { public, private: () };
///         let mut privatedata = PrivateContainer::default();
///         privatedata.push_private(PrivateValue::Octets32(private));
///         (public, privatedata)
///     }
///
///     fn merge(
///         public: Self::PublicView,
///         privatedata: &mut Self::PrivateData,
///     ) -> std::result::Result<Self, Self::MergeError> {
///         let Self::PublicView { public, .. } = public;
///         match privatedata.pop_private() {
///             Some(PrivateValue::Octets32(private)) => Ok(Self { public, private }),
///             _ => Err(MergeError::MissingPrivateData),
///         }
///     }
/// }
/// ```
pub trait PrivateParts: Sized {
    type PublicView;
    type PrivateData: PrivateDataContainer;
    type MergeError;

    /// Convert this object into the *public* version of itself, and return a vec of any private
    /// data contained in it. The order of the private data is important so it should not be
    /// modified. In general, the private data should be treated as opaque and immutable until it
    /// can be rejoined
    fn strip(self) -> (Self::PublicView, Self::PrivateData);

    /// Convert a public object and the private data object (returned from [`strip()`]) and combine
    /// them to form the original object pre-split().
    fn merge(public: Self::PublicView, private: &mut Self::PrivateData) -> core::result::Result<Self, Self::MergeError>;
}

impl<T> PrivateParts for Option<T>
where
    T: PrivateParts,
{
    type PublicView = Option<<T as PrivateParts>::PublicView>;
    type PrivateData = <T as PrivateParts>::PrivateData;
    type MergeError = <T as PrivateParts>::MergeError;

    fn strip(self) -> (Self::PublicView, Self::PrivateData) {
        let mut private_data: Self::PrivateData = Default::default();
        let public = self.map(|val| {
            let (public, mut private) = val.strip();
            while let Some(prv) = private.pop_private() {
                private_data.push_private(prv);
            }
            public
        });
        (public, private_data)
    }

    fn merge(public: Self::PublicView, private: &mut Self::PrivateData) -> core::result::Result<Self, Self::MergeError> {
        public.map(|val| <T as PrivateParts>::merge(val, private)).transpose()
    }
}
impl<T> PrivateParts for Vec<T>
where
    T: PrivateParts,
{
    type PublicView = Vec<<T as PrivateParts>::PublicView>;
    type PrivateData = <T as PrivateParts>::PrivateData;
    type MergeError = <T as PrivateParts>::MergeError;

    fn strip(self) -> (Self::PublicView, Self::PrivateData) {
        let mut private_data: Self::PrivateData = Default::default();
        let public = self
            .into_iter()
            .map(|val| {
                let (public, mut private) = val.strip();
                while let Some(prv) = private.pop_private() {
                    private_data.push_private(prv);
                }
                public
            })
            .collect::<Vec<_>>();
        (public, private_data)
    }

    fn merge(public: Self::PublicView, private: &mut Self::PrivateData) -> core::result::Result<Self, Self::MergeError> {
        public
            .into_iter()
            .map(|val| <T as PrivateParts>::merge(val, private))
            .collect::<Result<Vec<_>, Self::MergeError>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rasn::{
        AsnType, Decode, Decoder, Encode, Encoder,
        types::{
            Class, Constructed, Tag,
            fields::{Field, Fields},
        },
    };
    use std::collections::VecDeque;

    #[derive(Debug)]
    pub enum PrivateValue {
        Octets(Vec<u8>),
    }

    #[derive(Debug, Default)]
    struct PrivateContainer {
        values: VecDeque<PrivateValue>,
    }

    impl PrivateDataContainer for PrivateContainer {
        type Value = PrivateValue;
        fn push_private(&mut self, val: Self::Value) {
            self.values.push_front(val);
        }
        fn pop_private(&mut self) -> Option<Self::Value> {
            self.values.pop_back()
        }
    }

    impl From<Vec<PrivateValue>> for PrivateContainer {
        fn from(val: Vec<PrivateValue>) -> Self {
            Self {
                values: val.into_iter().collect::<VecDeque<_>>(),
            }
        }
    }

    impl PrivateData for Vec<u8> {}

    #[derive(Clone, Debug)]
    struct Key<M: PrivacyMode> {
        name: Vec<u8>,
        secret: M::Private<Vec<u8>>,
    }

    impl PrivateParts for Key<Full> {
        type PublicView = Key<Public>;
        type PrivateData = PrivateContainer;
        type MergeError = MergeError;

        fn strip(self) -> (Self::PublicView, Self::PrivateData) {
            let Self { name, secret } = self;
            let public = Self::PublicView { name, secret: () };
            let private = vec![PrivateValue::Octets(secret)].into();
            (public, private)
        }

        fn merge(public: Self::PublicView, private: &mut Self::PrivateData) -> std::result::Result<Self, Self::MergeError> {
            let Self::PublicView { name, .. } = public;
            match private.pop_private() {
                Some(PrivateValue::Octets(secret)) => Ok(Self { name, secret }),
                _ => Err(MergeError::MissingPrivateData),
            }
        }
    }

    #[derive(PrivateParts)]
    #[parts(private_data = "PrivateContainer")]
    enum TransactionBody<M: PrivacyMode> {
        SayHi { recipient: String, key: Key<M>, note: String },
        Rotate(Key<M>),
    }

    #[derive(PrivateParts)]
    #[parts(private_data = "PrivateContainer")]
    struct Transaction<M: PrivacyMode> {
        id: String,
        body: TransactionBody<M>,
    }

    #[test]
    fn splits_merges() {
        let tx = Transaction::<Full> {
            id: "tx1".into(),
            body: TransactionBody::SayHi {
                recipient: "alice".into(),
                key: Key {
                    name: vec![1, 2, 3],
                    secret: vec![4, 5, 6],
                },
                note: "hello".into(),
            },
        };
        assert_eq!(tx.id, "tx1");
        match &tx.body {
            TransactionBody::SayHi { recipient, key, note } => {
                assert_eq!(recipient, "alice");
                assert_eq!(key.name, vec![1, 2, 3]);
                assert_eq!(key.secret, vec![4, 5, 6]);
                assert_eq!(note, "hello");
            }
            _ => panic!(),
        }

        let (tx_pub, mut tx_prv) = tx.strip();
        assert_eq!(tx_pub.id, "tx1");
        match &tx_pub.body {
            TransactionBody::SayHi { recipient, key, note } => {
                assert_eq!(recipient, "alice");
                assert_eq!(key.name, vec![1, 2, 3]);
                assert_eq!(key.secret, ());
                assert_eq!(note, "hello");
            }
            _ => panic!(),
        }

        let tx_merged = Transaction::<Full>::merge(tx_pub, &mut tx_prv).unwrap();
        assert_eq!(tx_merged.id, "tx1");
        match &tx_merged.body {
            TransactionBody::SayHi { recipient, key, note } => {
                assert_eq!(recipient, "alice");
                assert_eq!(key.name, vec![1, 2, 3]);
                assert_eq!(key.secret, vec![4, 5, 6]);
                assert_eq!(note, "hello");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn enum_variants_strip() {
        let action = TransactionBody::<Full>::Rotate(Key {
            name: vec![9, 9, 9],
            secret: vec![8, 7, 6],
        });
        let (public, mut private) = action.strip();
        match &public {
            TransactionBody::Rotate(key) => {
                assert_eq!(key.name, vec![9, 9, 9]);
                assert_eq!(key.secret, ());
            }
            _ => panic!("unexpected variant"),
        }
        let merged = TransactionBody::<Full>::merge(public, &mut private).unwrap();
        match merged {
            TransactionBody::Rotate(key) => {
                assert_eq!(key.secret, vec![8, 7, 6]);
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn newtype() {
        #[derive(PrivateParts)]
        #[parts(private_data = "PrivateContainer")]
        struct MyKey<M: PrivacyMode>(Key<M>);

        let my_key = MyKey::<Full>(Key {
            name: vec![1, 2, 3],
            secret: vec![4, 5, 6],
        });

        let (stripped, mut prv) = my_key.strip();

        assert_eq!(stripped.0.name, vec![1, 2, 3]);
        assert_eq!(stripped.0.secret, ());

        let rebuilt = MyKey::<Full>::merge(stripped, &mut prv).unwrap();
        assert_eq!(rebuilt.0.name, vec![1, 2, 3]);
        assert_eq!(rebuilt.0.secret, vec![4, 5, 6]);
    }

    #[test]
    fn enum_variants() {
        #[derive(PrivateParts)]
        #[parts(private_data = "PrivateContainer")]
        enum MyVal<M: PrivacyMode> {
            Name(String),
            Key(Key<M>),
            Keys(Key<M>, Key<M>),
            KeysStruct { key1: Key<M>, key2: Key<M> },
            Nothing,
        }

        let value = MyVal::<Full>::Name("bob".into());
        let (public, mut private) = value.strip();
        match &public {
            MyVal::Name(name) => assert_eq!(name, "bob"),
            _ => panic!("expected Name variant"),
        }
        assert!(private.pop_private().is_none());
        let rebuilt = MyVal::<Full>::merge(public, &mut private).unwrap();
        match rebuilt {
            MyVal::Name(name) => assert_eq!(name, "bob"),
            _ => panic!("expected Name variant"),
        }

        let pair = MyVal::<Full>::Keys(
            Key {
                name: vec![4, 5, 6],
                secret: vec![7, 8, 9],
            },
            Key {
                name: vec![9, 8, 7],
                secret: vec![6, 5, 4],
            },
        );
        let (pair_public, mut pair_private) = pair.strip();
        match &pair_public {
            MyVal::Keys(first, second) => {
                assert_eq!(first.secret, ());
                assert_eq!(second.secret, ());
            }
            _ => panic!("expected Keys variant"),
        }
        let rebuilt_pair = MyVal::<Full>::merge(pair_public, &mut pair_private).unwrap();
        match rebuilt_pair {
            MyVal::Keys(first, second) => {
                assert_eq!(first.secret, vec![7, 8, 9]);
                assert_eq!(second.secret, vec![6, 5, 4]);
            }
            _ => panic!("expected Keys variant"),
        }

        let pair = MyVal::<Full>::KeysStruct {
            key1: Key {
                name: vec![4, 5, 6],
                secret: vec![7, 8, 9],
            },
            key2: Key {
                name: vec![9, 8, 7],
                secret: vec![6, 5, 4],
            },
        };
        let (pair_public, mut pair_private) = pair.strip();
        match &pair_public {
            MyVal::KeysStruct { key1: first, key2: second } => {
                assert_eq!(first.secret, ());
                assert_eq!(second.secret, ());
            }
            _ => panic!("expected Keys variant"),
        }
        let rebuilt_pair = MyVal::<Full>::merge(pair_public, &mut pair_private).unwrap();
        match rebuilt_pair {
            MyVal::KeysStruct { key1: first, key2: second } => {
                assert_eq!(first.secret, vec![7, 8, 9]);
                assert_eq!(second.secret, vec![6, 5, 4]);
            }
            _ => panic!("expected Keys variant"),
        }

        let nothing = MyVal::<Full>::Nothing;
        let (nothing_public, mut nothing_private) = nothing.strip();
        assert!(matches!(nothing_public, MyVal::Nothing));
        assert!(nothing_private.pop_private().is_none());
        let rebuilt_nothing = MyVal::<Full>::merge(nothing_public, &mut nothing_private).unwrap();
        assert!(matches!(rebuilt_nothing, MyVal::Nothing));
    }

    #[test]
    fn multiple_private_fields() {
        #[derive(PrivateParts)]
        #[parts(private_data = "PrivateContainer")]
        struct MultiKeys<M: PrivacyMode> {
            primary: Key<M>,
            secondary: Key<M>,
            note: String,
        }

        let multi = MultiKeys::<Full> {
            primary: Key {
                name: vec![1, 1, 1],
                secret: vec![2, 2, 2],
            },
            secondary: Key {
                name: vec![3, 3, 3],
                secret: vec![4, 4, 4],
            },
            note: "combo".into(),
        };

        let (public, mut private) = multi.strip();
        assert_eq!(private.values.len(), 2);
        assert_eq!(public.primary.secret, ());
        assert_eq!(public.secondary.secret, ());
        assert_eq!(public.note, "combo");

        let rebuilt = MultiKeys::<Full>::merge(public, &mut private).unwrap();
        assert_eq!(rebuilt.primary.secret, vec![2, 2, 2]);
        assert_eq!(rebuilt.secondary.secret, vec![4, 4, 4]);
        assert_eq!(rebuilt.note, "combo");

        // test From<Full> for Public
        let from = MultiKeys::<Public>::from(rebuilt);
        assert_eq!(from.primary.secret, ());
        assert_eq!(from.secondary.secret, ());
        assert_eq!(from.note, "combo");
    }

    #[test]
    fn recurse() {
        #[derive(Debug, PrivateParts)]
        #[parts(private_data = "PrivateContainer")]
        struct Keychain<M: PrivacyMode> {
            user_id: u32,
            keys: Vec<Key<M>>,
            admin_key: Option<Key<M>>,
        }

        let key1 = Key::<Full> {
            name: "jack".into(),
            secret: vec![0u8; 32],
        };

        let key2 = Key::<Full> {
            name: "jill".into(),
            secret: vec![1u8; 32],
        };

        let key3 = Key::<Full> {
            name: "jerry".into(),
            secret: vec![3u8; 32],
        };

        let keychain = Keychain::<Full> {
            user_id: 69,
            keys: vec![key1, key2],
            admin_key: Some(key3),
        };

        let (keychain_pub, mut keychain_prv) = PrivateParts::strip(keychain);

        assert_eq!(keychain_pub.user_id, 69);
        assert_eq!(keychain_pub.keys.len(), 2);
        assert_eq!(keychain_pub.keys[0].name, "jack".as_bytes());
        assert_eq!(keychain_pub.keys[0].secret, ());
        assert_eq!(keychain_pub.keys[1].name, "jill".as_bytes());
        assert_eq!(keychain_pub.keys[1].secret, ());
        assert_eq!(keychain_pub.admin_key.as_ref().unwrap().name, "jerry".as_bytes());
        assert_eq!(keychain_pub.admin_key.as_ref().unwrap().secret, ());

        let keychain_rebuilt = Keychain::<Full>::merge(keychain_pub, &mut keychain_prv).unwrap();

        assert_eq!(keychain_rebuilt.keys.len(), 2);
        assert_eq!(keychain_rebuilt.keys[0].name, "jack".as_bytes());
        assert_eq!(keychain_rebuilt.keys[0].secret, &[0u8; 32]);
        assert_eq!(keychain_rebuilt.keys[1].name, "jill".as_bytes());
        assert_eq!(keychain_rebuilt.keys[1].secret, &[1u8; 32]);
        assert_eq!(keychain_rebuilt.admin_key.as_ref().unwrap().name, "jerry".as_bytes());
        assert_eq!(keychain_rebuilt.admin_key.as_ref().unwrap().secret, &[3u8; 32]);
    }

    #[test]
    fn crypto_keypair() {
        /// A self-describing, encrypted object that can be opened with the right key.
        #[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
        #[rasn(delegate)]
        pub struct Sealed(Vec<u8>);

        impl PrivateData for Sealed {}

        /// Holds private data stripped from [`Full`] objects.
        #[derive(Debug, Clone, AsnType, Serialize, Deserialize)]
        #[allow(dead_code)]
        pub struct PrivateContainer {
            #[rasn(tag(explicit(0)))]
            values: Vec<Sealed>,
        }

        impl Default for PrivateContainer {
            fn default() -> Self {
                Self { values: Vec::new() }
            }
        }

        impl PrivateDataContainer for PrivateContainer {
            type Value = Sealed;

            fn push_private(&mut self, val: Self::Value) {
                self.values.push(val);
            }

            fn pop_private(&mut self) -> Option<Self::Value> {
                if !self.values.is_empty() {
                    Some(self.values.remove(0))
                } else {
                    None
                }
            }
        }

        /// Holds private data, which can only be opened if you have the special key.
        #[derive(Debug, Serialize, Deserialize)]
        #[allow(dead_code)]
        pub struct Private<M: PrivacyMode, T> {
            /// Allows us to cast this container to T without this container ever
            /// actually storing any T value (because it's encrypted).
            #[serde(skip)]
            _phantom: std::marker::PhantomData<T>,
            /// The encrypted data stored in this container, created using a
            /// `PrivateVerifiableInner` struct (the actual data alongside an HMAC key).
            sealed: M::Private<Sealed>,
        }

        impl<T> PrivateParts for Private<Full, T> {
            type PublicView = Private<Public, T>;
            type PrivateData = PrivateContainer;
            type MergeError = MergeError;

            fn strip(self) -> (Self::PublicView, Self::PrivateData) {
                let Self { sealed, _phantom } = self;
                let public = Self::PublicView {
                    sealed: (),
                    _phantom: std::marker::PhantomData,
                };
                let mut private = Self::PrivateData::default();
                private.push_private(sealed);
                (public, private)
            }

            fn merge(_public: Self::PublicView, private: &mut Self::PrivateData) -> std::result::Result<Self, Self::MergeError> {
                match private.pop_private() {
                    Some(sealed) => Ok(Self {
                        sealed,
                        _phantom: std::marker::PhantomData,
                    }),
                    _ => Err(MergeError::MissingPrivateData),
                }
            }
        }

        impl<M: PrivacyMode, T> AsnType for Private<M, T> {
            const TAG: Tag = Tag::SEQUENCE;
        }

        impl<M: PrivacyMode, T> Constructed<1, 0> for Private<M, T> {
            const FIELDS: Fields<1> = Fields::from_static([Field::new_required(0, Sealed::TAG, Sealed::TAG_TREE, "sealed")]);
        }

        impl<M: PrivacyMode, T> Encode for Private<M, T> {
            fn encode_with_tag_and_constraints<'encoder, E: Encoder<'encoder>>(
                &self,
                encoder: &mut E,
                tag: Tag,
                constraints: rasn::types::constraints::Constraints,
                identifier: rasn::types::Identifier,
            ) -> std::result::Result<(), E::Error> {
                encoder.encode_sequence::<1, 0, Self, _>(
                    tag,
                    |encoder| {
                        self.sealed
                            .encode_with_tag_and_constraints(encoder, Tag::new(Class::Context, 0), constraints, identifier)?;
                        Ok(())
                    },
                    identifier,
                )?;
                Ok(())
            }
        }

        impl<M: PrivacyMode, T> Decode for Private<M, T> {
            fn decode_with_tag_and_constraints<D: Decoder>(
                decoder: &mut D,
                tag: Tag,
                constraints: rasn::types::constraints::Constraints,
            ) -> std::result::Result<Self, D::Error> {
                decoder.decode_sequence(tag, None::<fn() -> Self>, |decoder| {
                    let sealed = M::Private::<Sealed>::decode_with_tag_and_constraints(decoder, Tag::new(Class::Context, 0), constraints)?;
                    Ok(Self {
                        _phantom: std::marker::PhantomData,
                        sealed,
                    })
                })
            }
        }

        impl<M: PrivacyMode, T> Clone for Private<M, T> {
            fn clone(&self) -> Self {
                Self {
                    _phantom: std::marker::PhantomData,
                    sealed: self.sealed.clone(),
                }
            }
        }

        /// An asymmetric signing keypair.
        #[derive(Clone, Debug, PrivateParts, AsnType, Encode, Decode, Serialize, Deserialize)]
        #[parts(private_data = "PrivateContainer")]
        #[rasn(choice)]
        #[allow(dead_code)]
        pub enum CryptoKeypair<M: PrivacyMode> {
            /// Curve25519XChaCha20Poly1305 keypair for encryption/decryption
            #[rasn(tag(explicit(0)))]
            Curve25519XChaCha20Poly1305 {
                #[rasn(tag(explicit(0)))]
                public: [u8; 32],
                #[rasn(tag(explicit(1)))]
                secret: Private<M, [u8; 32]>,
            },
        }
    }

    #[test]
    fn vec_clone() {
        fn dump_vals<M: PrivacyMode>(vals: Vec<Key<M>>) {
            drop(vals);
        }

        let keys = vec![
            Key::<Full> {
                name: Vec::from(b"strappy"),
                secret: Vec::from(b"shhhh1"),
            },
            Key::<Full> {
                name: Vec::from(b"slappy"),
                secret: Vec::from(b"shhhh2"),
            },
            Key::<Full> {
                name: Vec::from(b"clappy"),
                secret: Vec::from(b"shhhh3"),
            },
        ];

        let myref = &keys;

        dump_vals(myref.clone());
    }

    /*
    #[test]
    fn rasn_generic() {
        #[derive(AsnType, Encode, Decode)]
        #[rasn(choice)]
        #[allow(dead_code)]
        enum MyContainerExplicit<M> {
            HasGeneric {
                #[rasn(tag(explicit(0)))]
                inner: Vec<M>,
            },
            NoGeneric {
                #[rasn(tag(explicit(0)))]
                name: String,
            }
        }
    }
    */

    /*
    #[test]
    fn constraints() {
        #[derive(Debug)]
        struct Sealed(pub Vec<u8>);

        //#[derive(Debug)]
        struct Private<M: PrivacyMode, T> {
            _phantom: std::marker::PhantomData<T>,
            data: M::Private<Sealed>,
        }

        impl<M, T> std::fmt::Debug for Private<M, T>
        where
            M: PrivacyMode,
            M::Private<Sealed>: std::fmt::Debug,
        {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("Private").field("data", &self.data).finish()
            }
        }

        #[derive(Debug)]
        struct Container<M: PrivacyMode, T> {
            val: Private<M, T>,
        }

        #[derive(Debug)]
        struct Name<M: PrivacyMode> {
            val: Container<M, String>,
        }
    }
    */
}
