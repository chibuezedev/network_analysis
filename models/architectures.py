"""
Deep Learning Architectures for Network Intrusion Detection
multiple SOTA architectures with regularization to prevent overfitting
"""

import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, models, regularizers  # type: ignore
from tensorflow.keras.callbacks import (  # type: ignore
    EarlyStopping,
    ModelCheckpoint,
    ReduceLROnPlateau,
)


class IDSArchitectures:
    """Collection of state-of-the-art deep learning architectures"""

    @staticmethod
    def deep_mlp_with_attention(input_dim, num_classes=10, dropout_rate=0.4):
        """
        Deep MLP with Self-Attention mechanism
        Prevents overfitting through dropout, batch normalization, and L2 regularization
        """
        inputs = layers.Input(shape=(input_dim,))

        # First block
        x = layers.Dense(256, kernel_regularizer=regularizers.l2(0.001))(inputs)
        x = layers.BatchNormalization()(x)
        x = layers.Activation("relu")(x)
        x = layers.Dropout(dropout_rate)(x)

        # Second block
        x = layers.Dense(128, kernel_regularizer=regularizers.l2(0.001))(x)
        x = layers.BatchNormalization()(x)
        x = layers.Activation("relu")(x)
        x = layers.Dropout(dropout_rate)(x)

        # Attention mechanism
        attention = layers.Dense(128, activation="tanh")(x)
        attention = layers.Dense(128, activation="softmax")(attention)
        x = layers.Multiply()([x, attention])

        # Third block
        x = layers.Dense(64, kernel_regularizer=regularizers.l2(0.001))(x)
        x = layers.BatchNormalization()(x)
        x = layers.Activation("relu")(x)
        x = layers.Dropout(dropout_rate * 0.8)(x)

        # Fourth block
        x = layers.Dense(32, kernel_regularizer=regularizers.l2(0.001))(x)
        x = layers.BatchNormalization()(x)
        x = layers.Activation("relu")(x)
        x = layers.Dropout(dropout_rate * 0.6)(x)

        # Output
        outputs = layers.Dense(num_classes, activation="softmax")(x)

        model = models.Model(inputs=inputs, outputs=outputs, name="DeepMLP_Attention")
        return model

    @staticmethod
    def cnn_1d_architecture(input_dim, num_classes=10, dropout_rate=0.4):
        """
        1D CNN for pattern recognition in network features
        """
        inputs = layers.Input(shape=(input_dim, 1))

        x = layers.Conv1D(
            64, kernel_size=3, padding="same", kernel_regularizer=regularizers.l2(0.001)
        )(inputs)
        x = layers.BatchNormalization()(x)
        x = layers.Activation("relu")(x)
        x = layers.MaxPooling1D(pool_size=2)(x)
        x = layers.Dropout(dropout_rate)(x)

        x = layers.Conv1D(
            128,
            kernel_size=3,
            padding="same",
            kernel_regularizer=regularizers.l2(0.001),
        )(x)
        x = layers.BatchNormalization()(x)
        x = layers.Activation("relu")(x)
        x = layers.MaxPooling1D(pool_size=2)(x)
        x = layers.Dropout(dropout_rate)(x)

        x = layers.Conv1D(
            256,
            kernel_size=3,
            padding="same",
            kernel_regularizer=regularizers.l2(0.001),
        )(x)
        x = layers.BatchNormalization()(x)
        x = layers.Activation("relu")(x)
        x = layers.GlobalAveragePooling1D()(x)
        x = layers.Dropout(dropout_rate)(x)

        # Dense layers
        x = layers.Dense(128, kernel_regularizer=regularizers.l2(0.001))(x)
        x = layers.BatchNormalization()(x)
        x = layers.Activation("relu")(x)
        x = layers.Dropout(dropout_rate * 0.8)(x)

        # Output
        outputs = layers.Dense(num_classes, activation="softmax")(x)

        model = models.Model(inputs=inputs, outputs=outputs, name="CNN1D")
        return model

    @staticmethod
    def bidirectional_lstm(input_dim, num_classes=10, dropout_rate=0.4):
        """
        Bidirectional LSTM for temporal pattern detection
        """
        inputs = layers.Input(shape=(input_dim, 1))

        # First BiLSTM layer
        x = layers.Bidirectional(
            layers.LSTM(
                128,
                return_sequences=True,
                dropout=dropout_rate,
                recurrent_dropout=dropout_rate * 0.5,
                kernel_regularizer=regularizers.l2(0.001),
            )
        )(inputs)
        x = layers.BatchNormalization()(x)

        # Second BiLSTM layer
        x = layers.Bidirectional(
            layers.LSTM(
                64,
                return_sequences=True,
                dropout=dropout_rate,
                recurrent_dropout=dropout_rate * 0.5,
                kernel_regularizer=regularizers.l2(0.001),
            )
        )(x)
        x = layers.BatchNormalization()(x)

        # Attention layer
        attention = layers.Dense(1, activation="tanh")(x)
        attention = layers.Flatten()(attention)
        attention = layers.Activation("softmax")(attention)
        attention = layers.RepeatVector(128)(attention)
        attention = layers.Permute([2, 1])(attention)

        x = layers.Multiply()([x, attention])
        x = layers.GlobalAveragePooling1D()(x)

        # Dense layers
        x = layers.Dense(64, kernel_regularizer=regularizers.l2(0.001))(x)
        x = layers.BatchNormalization()(x)
        x = layers.Activation("relu")(x)
        x = layers.Dropout(dropout_rate * 0.8)(x)

        # Output
        outputs = layers.Dense(num_classes, activation="softmax")(x)

        model = models.Model(inputs=inputs, outputs=outputs, name="BiLSTM_Attention")
        return model

    @staticmethod
    def transformer_encoder(
        input_dim, num_classes=10, dropout_rate=0.4, num_heads=4, ff_dim=256
    ):
        """
        Transformer Encoder architecture for IDS
        """
        inputs = layers.Input(shape=(input_dim,))

        # Reshape for transformer
        x = layers.Reshape((input_dim, 1))(inputs)

        # Positional encoding
        positions = tf.range(start=0, limit=input_dim, delta=1)
        position_embedding = layers.Embedding(input_dim=input_dim, output_dim=1)(
            positions
        )
        x = x + position_embedding

        # Transformer block
        attention_output = layers.MultiHeadAttention(
            num_heads=num_heads, key_dim=1, dropout=dropout_rate
        )(x, x)
        attention_output = layers.Dropout(dropout_rate)(attention_output)
        x1 = layers.LayerNormalization(epsilon=1e-6)(x + attention_output)

        # Feed-forward network
        ff_output = layers.Dense(
            ff_dim, activation="relu", kernel_regularizer=regularizers.l2(0.001)
        )(x1)
        ff_output = layers.Dropout(dropout_rate)(ff_output)
        ff_output = layers.Dense(1, kernel_regularizer=regularizers.l2(0.001))(
            ff_output
        )
        ff_output = layers.Dropout(dropout_rate)(ff_output)
        x2 = layers.LayerNormalization(epsilon=1e-6)(x1 + ff_output)

        # Global pooling and dense layers
        x = layers.GlobalAveragePooling1D()(x2)
        x = layers.Dense(128, kernel_regularizer=regularizers.l2(0.001))(x)
        x = layers.BatchNormalization()(x)
        x = layers.Activation("relu")(x)
        x = layers.Dropout(dropout_rate)(x)

        x = layers.Dense(64, kernel_regularizer=regularizers.l2(0.001))(x)
        x = layers.BatchNormalization()(x)
        x = layers.Activation("relu")(x)
        x = layers.Dropout(dropout_rate * 0.8)(x)

        # Output
        outputs = layers.Dense(num_classes, activation="softmax")(x)

        model = models.Model(inputs=inputs, outputs=outputs, name="Transformer")
        return model

    @staticmethod
    def residual_network(input_dim, num_classes=10, dropout_rate=0.4):
        """
        ResNet-inspired architecture with skip connections
        """
        inputs = layers.Input(shape=(input_dim,))

        # Initial dense layer
        x = layers.Dense(256, kernel_regularizer=regularizers.l2(0.001))(inputs)
        x = layers.BatchNormalization()(x)
        x = layers.Activation("relu")(x)
        x = layers.Dropout(dropout_rate)(x)

        # Residual block 1
        residual = x
        x = layers.Dense(256, kernel_regularizer=regularizers.l2(0.001))(x)
        x = layers.BatchNormalization()(x)
        x = layers.Activation("relu")(x)
        x = layers.Dropout(dropout_rate)(x)
        x = layers.Dense(256, kernel_regularizer=regularizers.l2(0.001))(x)
        x = layers.BatchNormalization()(x)
        x = layers.Add()([x, residual])
        x = layers.Activation("relu")(x)

        # Residual block 2
        x = layers.Dense(128, kernel_regularizer=regularizers.l2(0.001))(x)
        x = layers.BatchNormalization()(x)
        x = layers.Activation("relu")(x)
        x = layers.Dropout(dropout_rate)(x)

        residual = x
        x = layers.Dense(128, kernel_regularizer=regularizers.l2(0.001))(x)
        x = layers.BatchNormalization()(x)
        x = layers.Activation("relu")(x)
        x = layers.Dropout(dropout_rate)(x)
        x = layers.Dense(128, kernel_regularizer=regularizers.l2(0.001))(x)
        x = layers.BatchNormalization()(x)
        x = layers.Add()([x, residual])
        x = layers.Activation("relu")(x)

        # Final dense layers
        x = layers.Dense(64, kernel_regularizer=regularizers.l2(0.001))(x)
        x = layers.BatchNormalization()(x)
        x = layers.Activation("relu")(x)
        x = layers.Dropout(dropout_rate * 0.8)(x)

        # Output
        outputs = layers.Dense(num_classes, activation="softmax")(x)

        model = models.Model(inputs=inputs, outputs=outputs, name="ResNet")
        return model

    @staticmethod
    def ensemble_model(input_dim, num_classes=10, dropout_rate=0.4):
        """
        Ensemble of multiple architectures for robust predictions
        """
        inputs = layers.Input(shape=(input_dim,))

        # Branch 1: Deep MLP
        mlp = layers.Dense(
            128, activation="relu", kernel_regularizer=regularizers.l2(0.001)
        )(inputs)
        mlp = layers.BatchNormalization()(mlp)
        mlp = layers.Dropout(dropout_rate)(mlp)
        mlp = layers.Dense(
            64, activation="relu", kernel_regularizer=regularizers.l2(0.001)
        )(mlp)
        mlp = layers.BatchNormalization()(mlp)

        # Branch 2: 1D CNN path
        cnn_input = layers.Reshape((input_dim, 1))(inputs)
        cnn = layers.Conv1D(
            64, 3, padding="same", kernel_regularizer=regularizers.l2(0.001)
        )(cnn_input)
        cnn = layers.BatchNormalization()(cnn)
        cnn = layers.Activation("relu")(cnn)
        cnn = layers.GlobalAveragePooling1D()(cnn)
        cnn = layers.Dropout(dropout_rate)(cnn)

        # Branch 3: Attention path
        attn = layers.Dense(
            128, activation="tanh", kernel_regularizer=regularizers.l2(0.001)
        )(inputs)
        attn_weights = layers.Dense(128, activation="softmax")(attn)
        attn = layers.Multiply()([attn, attn_weights])
        attn = layers.Dropout(dropout_rate)(attn)

        # Concatenate all branches
        concat = layers.Concatenate()([mlp, cnn, attn])

        # Final processing
        x = layers.Dense(128, kernel_regularizer=regularizers.l2(0.001))(concat)
        x = layers.BatchNormalization()(x)
        x = layers.Activation("relu")(x)
        x = layers.Dropout(dropout_rate)(x)

        x = layers.Dense(64, kernel_regularizer=regularizers.l2(0.001))(x)
        x = layers.BatchNormalization()(x)
        x = layers.Activation("relu")(x)
        x = layers.Dropout(dropout_rate * 0.8)(x)

        # Output
        outputs = layers.Dense(num_classes, activation="softmax")(x)

        model = models.Model(inputs=inputs, outputs=outputs, name="Ensemble")
        return model


def get_callbacks(model_path, patience=15):
    """
    Get training callbacks to prevent overfitting

    Args:
        model_path: Path to save best model
        patience: Early stopping patience

    Returns:
        List of callbacks
    """
    callbacks = [
        EarlyStopping(
            monitor="val_loss",
            patience=patience,
            restore_best_weights=True,
            verbose=1,
            mode="min",
        ),
        ReduceLROnPlateau(
            monitor="val_loss",
            factor=0.5,
            patience=7,
            min_lr=1e-7,
            verbose=1,
            mode="min",
        ),
        ModelCheckpoint(
            filepath=model_path,
            monitor="val_accuracy",
            save_best_only=True,
            save_weights_only=False,
            mode="max",
            verbose=1,
        ),
    ]

    return callbacks


def compile_model(model, learning_rate=0.001):
    """
    Compile model with optimizer and loss

    Args:
        model: Keras model
        learning_rate: Initial learning rate
    """
    optimizer = keras.optimizers.Adam(
        learning_rate=learning_rate,
        clipnorm=1.0,
    )

    model.compile(
        optimizer=optimizer,
        loss="sparse_categorical_crossentropy",
        metrics=[
            "accuracy",
            # keras.metrics.Precision(name="precision"),
            # keras.metrics.Recall(name="recall"),
        ],
    )

    return model
