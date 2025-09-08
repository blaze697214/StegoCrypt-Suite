// cyber_widgets.dart
import 'package:flutter/material.dart';
import 'cyber_theme.dart';

enum CyberButtonVariant { primary, secondary, outline, ghost, danger }

class CyberButton extends StatefulWidget {
  final String text;
  final VoidCallback? onPressed;
  final CyberButtonVariant variant;
  final IconData? icon;
  final bool isLoading;
  final double? width;
  final double height;
  final bool isGlowing;

  const CyberButton({
    super.key,
    required this.text,
    required this.onPressed,
    this.variant = CyberButtonVariant.primary,
    this.icon,
    this.isLoading = false,
    this.width,
    this.height = 48,
    this.isGlowing = false,
  });

  @override
  _CyberButtonState createState() => _CyberButtonState();
}

class _CyberButtonState extends State<CyberButton>
    with TickerProviderStateMixin {
  late AnimationController _hoverController;
  late AnimationController _pressController;
  late AnimationController _glowController;
  late Animation<double> _hoverAnimation;
  late Animation<double> _pressAnimation;
  late Animation<double> _glowAnimation;

  bool _isHovered = false;

  @override
  void initState() {
    super.initState();
    _initAnimations();
  }

  void _initAnimations() {
    _hoverController = AnimationController(
      duration: CyberTheme.fastAnimation,
      vsync: this,
    );

    _pressController = AnimationController(
      duration: const Duration(milliseconds: 100),
      vsync: this,
    );

    _glowController = AnimationController(
      duration: const Duration(seconds: 2),
      vsync: this,
    );

    _hoverAnimation = Tween<double>(begin: 1.0, end: 1.05).animate(
      CurvedAnimation(parent: _hoverController, curve: CyberTheme.smoothCurve),
    );

    _pressAnimation = Tween<double>(
      begin: 1.0,
      end: 0.95,
    ).animate(CurvedAnimation(parent: _pressController, curve: Curves.easeOut));

    _glowAnimation = Tween<double>(begin: 0.5, end: 1.0).animate(
      CurvedAnimation(parent: _glowController, curve: Curves.easeInOut),
    );

    if (widget.isGlowing) {
      _glowController.repeat(reverse: true);
    }
  }

  @override
  void dispose() {
    _hoverController.dispose();
    _pressController.dispose();
    _glowController.dispose();
    super.dispose();
  }

  void _onTapDown(TapDownDetails details) {
    _pressController.forward();
  }

  void _onTapUp(TapUpDetails details) {
    _pressController.reverse();
  }

  void _onTapCancel() {
    _pressController.reverse();
  }

  void _onHover(bool hovering) {
    setState(() {
      _isHovered = hovering;
    });

    if (hovering) {
      _hoverController.forward();
    } else {
      _hoverController.reverse();
    }
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: Listenable.merge([
        _hoverAnimation,
        _pressAnimation,
        _glowAnimation,
      ]),
      builder: (context, child) {
        return Transform.scale(
          scale: _hoverAnimation.value * _pressAnimation.value,
          child: Container(
            width: widget.width,
            height: widget.height,
            decoration: _getButtonDecoration(),
            child: Material(
              color: Colors.transparent,
              borderRadius: BorderRadius.circular(16),
              child: InkWell(
                borderRadius: BorderRadius.circular(16),
                onTap: widget.isLoading ? null : widget.onPressed,
                onTapDown: _onTapDown,
                onTapUp: _onTapUp,
                onTapCancel: _onTapCancel,
                onHover: _onHover,
                child: Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 24,
                    vertical: 12,
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      if (widget.isLoading)
                        SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(
                            strokeWidth: 2,
                            valueColor: AlwaysStoppedAnimation<Color>(
                              _getTextColor(),
                            ),
                          ),
                        )
                      else if (widget.icon != null)
                        Icon(widget.icon, size: 18, color: _getTextColor()),
                      if ((widget.icon != null && !widget.isLoading) ||
                          widget.isLoading)
                        const SizedBox(width: 8),
                      Text(
                        widget.text,
                        style: CyberTheme.bodyMedium.copyWith(
                          color: _getTextColor(),
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        );
      },
    );
  }

  BoxDecoration _getButtonDecoration() {
    List<BoxShadow> shadows = [];

    switch (widget.variant) {
      case CyberButtonVariant.primary:
        shadows = [
          BoxShadow(
            color: CyberTheme.cyberPurple.withOpacity(_isHovered ? 0.5 : 0.3),
            blurRadius: _isHovered ? 20 : 12,
            offset: const Offset(0, 6),
            spreadRadius: _isHovered ? 2 : 0,
          ),
        ];

        if (widget.isGlowing) {
          shadows.add(
            BoxShadow(
              color: CyberTheme.cyberPurple.withOpacity(
                _glowAnimation.value * 0.8,
              ),
              blurRadius: 30,
              spreadRadius: 5,
            ),
          );
        }

        return BoxDecoration(
          gradient: CyberTheme.primaryGradient,
          borderRadius: BorderRadius.circular(16),
          boxShadow: shadows,
        );

      case CyberButtonVariant.secondary:
        return BoxDecoration(
          gradient: CyberTheme.secondaryGradient,
          borderRadius: BorderRadius.circular(16),
          boxShadow: [
            BoxShadow(
              color: CyberTheme.aquaBlue.withOpacity(_isHovered ? 0.4 : 0.2),
              blurRadius: _isHovered ? 16 : 8,
              offset: const Offset(0, 4),
            ),
          ],
        );

      case CyberButtonVariant.outline:
        return BoxDecoration(
          color: Colors.transparent,
          borderRadius: BorderRadius.circular(16),
          border: Border.all(
            color: _isHovered ? CyberTheme.cyberPurple : CyberTheme.softGray,
            width: 2,
          ),
          boxShadow: _isHovered
              ? [
                  BoxShadow(
                    color: CyberTheme.cyberPurple.withOpacity(0.3),
                    blurRadius: 12,
                    spreadRadius: 1,
                  ),
                ]
              : null,
        );

      case CyberButtonVariant.ghost:
        return BoxDecoration(
          color: _isHovered ? CyberTheme.glowWhite : Colors.transparent,
          borderRadius: BorderRadius.circular(16),
        );

      case CyberButtonVariant.danger:
        return BoxDecoration(
          gradient: LinearGradient(
            colors: [CyberTheme.neonPink, Colors.red.shade400],
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
          ),
          borderRadius: BorderRadius.circular(16),
          boxShadow: [
            BoxShadow(
              color: CyberTheme.neonPink.withOpacity(_isHovered ? 0.5 : 0.3),
              blurRadius: _isHovered ? 20 : 12,
              offset: const Offset(0, 6),
            ),
          ],
        );
    }
  }

  Color _getTextColor() {
    switch (widget.variant) {
      case CyberButtonVariant.primary:
      case CyberButtonVariant.secondary:
      case CyberButtonVariant.danger:
        return Colors.white;
      case CyberButtonVariant.outline:
        return _isHovered ? CyberTheme.cyberPurple : CyberTheme.softGray;
      case CyberButtonVariant.ghost:
        return Colors.white;
    }
  }
}

class CyberSearchBar extends StatefulWidget {
  final String hintText;
  final ValueChanged<String>? onChanged;
  final VoidCallback? onSearch;

  const CyberSearchBar({
    super.key,
    required this.hintText,
    this.onChanged,
    this.onSearch,
  });

  @override
  _CyberSearchBarState createState() => _CyberSearchBarState();
}

class _CyberSearchBarState extends State<CyberSearchBar>
    with SingleTickerProviderStateMixin {
  late AnimationController _focusController;
  late Animation<Color?> _borderColorAnimation;
  final FocusNode _focusNode = FocusNode();
  bool _isFocused = false;

  @override
  void initState() {
    super.initState();
    _focusController = AnimationController(
      duration: CyberTheme.fastAnimation,
      vsync: this,
    );

    _borderColorAnimation = ColorTween(
      begin: CyberTheme.softGray.withOpacity(0.3),
      end: CyberTheme.cyberPurple,
    ).animate(_focusController);

    _focusNode.addListener(() {
      setState(() {
        _isFocused = _focusNode.hasFocus;
      });

      if (_focusNode.hasFocus) {
        _focusController.forward();
      } else {
        _focusController.reverse();
      }
    });
  }

  @override
  void dispose() {
    _focusController.dispose();
    _focusNode.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _borderColorAnimation,
      builder: (context, child) {
        return Container(
          height: 48,
          decoration: BoxDecoration(
            color: CyberTheme.glassWhite,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(
              color: _borderColorAnimation.value!,
              width: _isFocused ? 2 : 1,
            ),
            boxShadow: _isFocused
                ? [
                    BoxShadow(
                      color: CyberTheme.cyberPurple.withOpacity(0.2),
                      blurRadius: 12,
                      spreadRadius: 1,
                    ),
                  ]
                : null,
          ),
          child: Row(
            children: [
              const SizedBox(width: 16),
              Icon(
                Icons.search,
                size: 20,
                color:
                    _isFocused ? CyberTheme.cyberPurple : CyberTheme.softGray,
              ),
              const SizedBox(width: 12),
              Expanded(
                child: TextField(
                  focusNode: _focusNode,
                  onChanged: widget.onChanged,
                  style: CyberTheme.bodyMedium,
                  decoration: InputDecoration(
                    hintText: widget.hintText,
                    hintStyle: CyberTheme.bodyMedium.copyWith(
                      color: CyberTheme.softGray,
                    ),
                    border: InputBorder.none,
                    contentPadding: EdgeInsets.zero,
                  ),
                ),
              ),
              if (_isFocused) ...[
                const SizedBox(width: 8),
                Material(
                  color: Colors.transparent,
                  borderRadius: BorderRadius.circular(8),
                  child: InkWell(
                    borderRadius: BorderRadius.circular(8),
                    onTap: widget.onSearch,
                    child: Container(
                      padding: const EdgeInsets.all(8),
                      child: const Icon(
                        Icons.keyboard_return,
                        size: 16,
                        color: CyberTheme.cyberPurple,
                      ),
                    ),
                  ),
                ),
              ],
              const SizedBox(width: 16),
            ],
          ),
        );
      },
    );
  }
}
